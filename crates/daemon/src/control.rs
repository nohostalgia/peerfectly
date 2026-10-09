//! What a person can ask the daemon, and what it answers.
//!
//! # Known and last known are different things
//!
//! §2.6c says the daemon reaches no infrastructure while the tunnel is down. A
//! consequence nobody would think to ask for: while it is down, everything the
//! daemon knows about other devices is **old**, and it has no way to find out
//! otherwise without breaking the property.
//!
//! So every answer carries whether it is current or remembered, and a remembered
//! one carries when it was true. A status display that shows a peer as reachable
//! because it was reachable last night is not a small inaccuracy — it is the
//! failure mode §2.6c's own consequences call the most dangerous in the system,
//! where a person believes a revocation has taken effect and it is sitting in a
//! queue.

use core::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use roster::id::DeviceId;
use serde::{Deserialize, Serialize};

pub mod framing;

/// Whether an answer is true now or was true once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Standing {
    /// The network is up and this was true when asked.
    Current,
    /// The network is down; this is the last thing that was known, and when.
    LastKnown {
        /// When it was last true.
        at: SystemTime,
    },
}

impl Standing {
    /// Whether this is a live answer.
    #[must_use]
    pub const fn is_current(&self) -> bool {
        matches!(self, Self::Current)
    }
}

impl fmt::Display for Standing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Current => f.write_str("now"),
            // **The epoch is nothing known**, not a date: a network founded or
            // joined and never up here has recorded no moment, and "1970-01-01
            // (20726 days ago)" is the zero it was stored as. The phone already
            // reads it so (`Times.kt`); this is the same rule, in the same words.
            Self::LastKnown { at } if crate::drawing::nothing_known(*at) => {
                f.write_str("last known: nothing seen yet")
            }
            Self::LastKnown { at } => write!(f, "last known at {}", crate::drawing::when(*at)),
        }
    }
}

/// Whether the tunnel is carrying traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tunnel {
    /// Up, and the person put it there.
    Up,
    /// Down.
    Down,
}

impl fmt::Display for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Up => "up",
            Self::Down => "down",
        })
    }
}

/// What the tray should show next, or `None` if it already shows it.
///
/// Pure, and separate from the icon, so "it changes on up and on down" is a
/// thing a test can assert. The icon itself needs a desktop session; deciding
/// when it must be redrawn does not, and that is the half that can be wrong in a
/// way a person notices — an icon that says the network is off while it is on is
/// worse than no icon at all.
#[must_use]
pub const fn redraw(shown: Tunnel, current: Tunnel) -> Option<Tunnel> {
    if matches!((shown, current), (Tunnel::Up, Tunnel::Up) | (Tunnel::Down, Tunnel::Down)) {
        None
    } else {
        Some(current)
    }
}

/// A short form of a device's id, the same wherever the device appears.
///
/// A name is not an identity. The roster bounds a name's length and nothing
/// else, so two admins admitting a `phone` while apart give a network two
/// devices called `phone`, and a revoked device's name can be taken by one
/// admitted later. This is what tells them apart.
///
/// The first 8 bytes, as `xxxx-xxxx-xxxx-xxxx`. Sixty-four bits because the
/// length that matters is how hard it is to produce a device matching a
/// *particular* one: an accomplice who could grind a twin of the laptop somebody
/// is about to revoke would have its name and its identifier both. Four bytes
/// fall to a laptop in minutes; eight do not.
#[must_use]
pub fn short_id(device: &DeviceId) -> String {
    let hex = device.to_hex();
    let digits = hex.get(..SHORT_ID_DIGITS).unwrap_or(&hex);
    digits
        .as_bytes()
        .chunks(4)
        .map(|group| core::str::from_utf8(group).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

/// How many hex digits a short id carries.
const SHORT_ID_DIGITS: usize = 16;

/// A short id as a person typed it, if it is one.
///
/// All sixteen digits, dashes optional and case ignored. Anything shorter is not
/// an id: revoking is irreversible, and a prefix that happened to match one
/// device today is a typo that matches another tomorrow.
#[must_use]
pub fn read_short_id(typed: &str) -> Option<String> {
    let digits: String = typed.chars().filter(|ch| *ch != '-').collect();
    if digits.len() != SHORT_ID_DIGITS || !digits.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    let lower = digits.to_ascii_lowercase();
    Some(
        lower
            .as_bytes()
            .chunks(4)
            .map(|group| core::str::from_utf8(group).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("-"),
    )
}

/// Text another device wrote, rendered so that it is seen and not obeyed.
///
/// Names, revocation reasons, relay addresses: every one of them was signed by a
/// device other than the one showing it. An escape sequence in a name repaints a
/// terminal; a right-to-left override makes one name display as another; a
/// zero-width space makes two names that differ look identical. Each of those is
/// an attack carried by a field this report exists to show.
///
/// So those characters are written as `\u{…}`, and a backslash as `\\` so that a
/// name cannot pretend to contain an escape. Everything else — `città`, `東京` —
/// is written as itself: a neutraliser that mangled legitimate names would be
/// removed by the first person whose name it mangled.
///
/// What this does not catch is a lookalike letter. A Cyrillic `а` in `lаptop` is
/// an ordinary letter. The short id beside every name is the defence there.
///
/// The report itself carries the text exactly as signed; this is only how the
/// command line draws it. Any other surface that renders a report owes the same.
#[must_use]
pub const fn shown(text: &str) -> Shown<'_> {
    Shown(text)
}

/// See [`shown`].
#[derive(Debug, Clone, Copy)]
pub struct Shown<'a>(&'a str);

impl fmt::Display for Shown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for ch in self.0.chars() {
            if ch == '\\' {
                f.write_str("\\\\")?;
            } else if disguises(ch) {
                write!(f, "\\u{{{:04x}}}", u32::from(ch))?;
            } else {
                fmt::Write::write_char(f, ch)?;
            }
        }
        Ok(())
    }
}

/// Whether a character changes how the text around it is drawn, or is invisible.
///
/// A fixed list in code rather than Unicode tables: these are the classes that
/// act on a terminal or on the direction and visibility of text, and a list that
/// can be read is a list that can be checked.
fn disguises(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            // Arabic letter mark, and the left-to-right and right-to-left marks.
            '\u{061C}' | '\u{200E}' | '\u{200F}'
            // Embeddings, overrides and their terminator.
            | '\u{202A}'..='\u{202E}'
            // Isolates.
            | '\u{2066}'..='\u{2069}'
            // Zero-width space, non-joiner and joiner; word joiner and the
            // invisible operators beside it; the byte-order mark.
            | '\u{200B}'..='\u{200D}'
            | '\u{2060}'..='\u{2064}'
            | '\u{FEFF}'
            // Line and paragraph separators.
            | '\u{2028}' | '\u{2029}'
        )
}

/// A device, as the report names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Named {
    /// The name it answers to, or was admitted under.
    ///
    /// `None` when nothing this roster still holds names the device — a revoked
    /// device whose admission a snapshot discarded. Listed anyway, by id: a list
    /// that dropped it would say it was never expelled.
    pub name: Option<String>,
    /// Its short id.
    pub id: String,
}

impl Named {
    /// A device with the name it goes by.
    #[must_use]
    pub fn new(device: &DeviceId, name: Option<String>) -> Self {
        Self { name, id: short_id(device) }
    }
}

impl fmt::Display for Named {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(name) => write!(f, "{} [{}]", shown(name), self.id),
            None => write!(f, "[{}] (no name held here)", self.id),
        }
    }
}

/// When this device was last in contact with another.
///
/// A variant rather than an `Option`, so that nothing renders the absence as
/// "never". A device in contact before this record existed has none recorded,
/// and "never" would be false.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Contact {
    /// A session with it last spoke in the minute starting at this time.
    Recorded {
        /// The start of that minute, on this device's clock.
        at: SystemTime,
    },
    /// No contact with it is recorded on this device.
    NoneRecorded,
}

impl fmt::Display for Contact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recorded { at } => {
                write!(f, "last contact with this device at {}", crate::drawing::when(*at))
            }
            Self::NoneRecorded => f.write_str("no contact with this device recorded"),
        }
    }
}

/// The time an operation carries, if it carries one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signed {
    /// The clock of whoever signed it said this.
    At {
        /// The time, floored to the minute by any daemon that signs with one.
        time: SystemTime,
    },
    /// It carries no plausible time — every operation this daemon signed before
    /// it put one there carries a counter instead.
    NotRecorded,
}

impl Signed {
    /// Reads an operation's time field.
    #[must_use]
    pub fn from_ts(ts: u64) -> Self {
        crate::clock::operation_time(ts).map_or(Self::NotRecorded, |time| Self::At { time })
    }
}

/// What an operation does, and to whom.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Act {
    /// Creates the network.
    Founds,
    /// Admits a device.
    Admits(Named),
    /// Revokes a device.
    Revokes(Named),
    /// Makes a device an admin, and a founder if the flag says so.
    Promotes(Named, bool),
    /// Makes an admin a member.
    Demotes(Named),
    /// Gives a device a new name.
    Renames(Named, String),
    /// Replaces the network's parameters.
    SetsParameters,
}

impl Act {
    /// Whether this is a revocation — the act whose non-arrival leaves a device
    /// admitted somewhere.
    #[must_use]
    pub const fn is_revocation(&self) -> bool {
        matches!(self, Self::Revokes(_))
    }
}

impl fmt::Display for Act {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Founds => f.write_str("the founding of this network"),
            Self::Admits(device) => write!(f, "admission of {device}"),
            Self::Revokes(device) => write!(f, "revocation of {device}"),
            Self::Promotes(device, false) => write!(f, "promotion of {device} to admin"),
            Self::Promotes(device, true) => {
                write!(f, "promotion of {device} to admin and founder")
            }
            Self::Demotes(device) => write!(f, "demotion of {device} to member"),
            // Once the rename is in force here, the name the device goes by
            // is the new one: by id alone then, not "renaming of studio to
            // studio".
            Self::Renames(device, to) if device.name.as_ref() == Some(to) => {
                write!(f, "renaming of [{}] to {}", device.id, shown(to))
            }
            Self::Renames(device, to) => write!(f, "renaming of {device} to {}", shown(to)),
            Self::SetsParameters => f.write_str("a change to the network's parameters"),
        }
    }
}

/// A device's IPv4 address in a network, or why it has none here.
///
/// An address that silently is not there looks like the network being broken.
/// Saying why tells a person whether to use the name, the IPv6 address, or move
/// the network to another range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ipv4State {
    /// It holds this address, and it is usable on this device.
    Held(Ipv4Addr),
    /// The network gives it none: this device derives the same address, and
    /// neither holds it.
    Collides(Named),
    /// It holds this address, and this device withholds it.
    Withheld {
        /// The address it holds in the network.
        address: Ipv4Addr,
        /// What it conflicts with on this device, in words.
        with: String,
    },
}

impl fmt::Display for Ipv4State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Held(address) => write!(f, "{address}"),
            Self::Collides(other) => {
                write!(f, "no IPv4: its address collides with {other}")
            }
            Self::Withheld { address, with } => {
                write!(f, "IPv4 {address} withheld here: it conflicts with {}", shown(with))
            }
        }
    }
}

/// How a peer's session travels, as the transport said when the report was built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Path {
    /// Straight to the peer.
    Direct,
    /// Through the network's relay: slower, for reasons that have nothing to do
    /// with the network's configuration.
    Relay,
}

impl From<transport::Path> for Path {
    fn from(path: transport::Path) -> Self {
        match path {
            transport::Path::Direct => Self::Direct,
            transport::Path::Relay => Self::Relay,
        }
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => f.write_str("direct"),
            Self::Relay => f.write_str("via relay"),
        }
    }
}

/// What a report from before [`Peer::name_resolves`] is read as.
const fn name_resolves_by_default() -> bool {
    true
}

/// One other device, as the daemon can describe it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    /// Its name under the network's suffix.
    pub name: String,
    /// Whether that name can be looked up. A name admitted before names were
    /// held to a DNS label may hold a space, an apostrophe or a dot, and then
    /// nobody reaches the device by it until an admin renames it. Absent from an
    /// older daemon's report, where it reads as `true`.
    #[serde(default = "name_resolves_by_default")]
    pub name_resolves: bool,
    /// Its short id.
    pub id: String,
    /// Its overlay address.
    pub address: Ipv6Addr,
    /// Its IPv4 address, or why it has none here.
    pub ipv4: Option<Ipv4State>,
    /// Whether a session to it exists now, or existed once.
    pub reachable: bool,
    /// How its session travels, while one is open and the transport can tell.
    pub path: Option<Path>,
    /// Whether the line above is current or remembered.
    pub standing: Standing,
    /// When this device last had a session with it that spoke.
    pub last_contact: Contact,
}

/// A device this device holds as revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revoked {
    /// The device, by the name it was admitted under.
    ///
    /// Admitted, not current: a revoked device has no current name, and
    /// reconstructing the one it had when it was revoked would be a second
    /// derivation of the roster to get wrong.
    pub device: Named,
    /// Every revocation of it held here. Two admins can each revoke it.
    pub revocations: Vec<Revocation>,
    /// When this device last had a session with it that spoke.
    pub last_contact: Contact,
}

/// One signed revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    /// The admin that signed it.
    pub by: Named,
    /// Why, as that admin wrote it.
    pub reason: String,
    /// What the revoking device's clock said. A claim, not a fact about when.
    pub signer_clock: Signed,
}

/// A device the roster has evidence against, and the evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accused {
    /// The device that signed both histories.
    pub device: Named,
    /// How many conflicting pairs from it are held. One is shown.
    ///
    /// A device can produce evidence against itself without limit, and every pair
    /// of its concurrent operations counts, so the pairs are counted rather than
    /// listed.
    pub pairs: usize,
    /// One of the two operations.
    pub first: Branch,
    /// The other.
    pub second: Branch,
}

/// One branch of an equivocation.
///
/// Deliberately without a time. Both operations were signed by the accused, so
/// their times are its own account of when it acted, and a person comparing two
/// branches by time would be comparing claims made by the party under suspicion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Branch {
    /// What the operation does.
    pub does: Act,
    /// Its causal depth, while the roster still holds its place in the history.
    pub depth: Option<u64>,
}

/// An operation signed here that some member has not said it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Waiting {
    /// What it does.
    pub does: Act,
    /// When this device signed it, on this device's own clock.
    pub signed_here: Signed,
    /// Every member that has not said it holds it.
    pub owed: Vec<Owed>,
}

/// A member an operation is owed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owed {
    /// The member.
    pub device: Named,
    /// Whether a session with it is open now.
    pub connected: bool,
    /// When this device last had a session with it that spoke.
    pub last_contact: Contact,
}

/// Where a network's signing key is kept, on **this** device.
///
/// A fact about this device alone. It is never said about a peer: this device
/// cannot observe how somebody else holds their key, and stating it would be
/// presenting an assumption as an observation — the thing §2.5 is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Custody {
    /// In a key store that will not give it up, and asks before it signs.
    KeyStore,
    /// In a file this device holds, protected as the platform protects a local
    /// secret.
    ///
    /// On a machine with no key store that could do better this is the honest
    /// answer and the only one; on a machine that has one it is a network that
    /// predates this and is refused rather than carried.
    HeldHere,
    /// In a file this device holds, sealed with a passphrase a person chose.
    ///
    /// Its own kind, and **never** reported as a key store: whoever obtains the
    /// file can try passphrases away from this machine for as long as they
    /// like, so the passphrase is the whole of the protection. A person reading
    /// the report must be able to tell that from a key that never leaves the
    /// hardware.
    Passphrase,
}

impl fmt::Display for Custody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyStore => f.write_str("in this machine's key store"),
            Self::HeldHere => f.write_str("in a file on this device"),
            Self::Passphrase => f.write_str("in a file sealed with a passphrase"),
        }
    }
}

/// A relay a network is moving away from, and when it stops being used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayLeaving {
    /// The relay being left.
    pub relay: String,
    /// When everybody moves off it.
    pub until: SystemTime,
}

/// One network this device holds, as the report describes it.
///
/// Everything here belongs to one network and is true of no other. A report that
/// gathered faults, peers or outstanding operations across networks would be
/// attributing one network's trouble to another, which is worse than saying
/// less.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    /// What this device calls it.
    pub label: String,
    /// Whether its tunnel is up.
    pub tunnel: Tunnel,
    /// Whether the lines below are current or remembered.
    pub standing: Standing,
    /// This device's own overlay address in it, once the parameters are known.
    pub address: Option<Ipv6Addr>,
    /// This device's own IPv4 address in it, or why it has none, once the roster
    /// holds this device.
    pub ipv4: Option<Ipv4State>,
    /// This device's own name in it, under the network's suffix, once the roster
    /// holds it.
    ///
    /// Reported so that a surface showing "this device, here" shows the name the
    /// other devices see, and not the local label, which nobody else sees.
    pub name: Option<String>,
    /// This device's own short id in it. Each network gives the device a different
    /// identity, so this is true of this network only.
    pub id: String,
    /// Whether this device is an admin of it, and so may admit and revoke.
    ///
    /// A surface offers those acts only where this holds. Offering them elsewhere
    /// would be offering something the roster refuses after the lock was asked for.
    pub admin: bool,
    /// Where this device keeps this network's signing key.
    pub custody: Custody,
    /// Whether this network was taken from somebody rather than always this
    /// person's.
    ///
    /// Said rather than left to look as though it had always been so. A network
    /// changing hands is a thing that happened, and a report that showed only
    /// the result would make a quiet act of a deliberate one.
    pub owner_taken: bool,
    /// The relay it uses, as its roster names it.
    ///
    /// Reported because the daemon and the person looking at it can be reading
    /// two different rosters: the daemon elevated and writing to one profile, a
    /// command run as the person and writing to another. Nothing else in this
    /// report would show it, and it cost a day of two-machine testing once.
    pub relay: Option<String>,
    /// The rendezvous it uses, as its roster names it.
    pub rendezvous: Option<String>,
    /// Whether that roster pins the relay's certificate.
    ///
    /// Without a pin a relay presenting a self-signed certificate is refused, no
    /// device registers a home relay, and every peer reads `not reachable` with
    /// no mention of a certificate anywhere.
    pub relay_pinned: bool,
    /// The relay this network is moving away from, while the move lasts.
    ///
    /// **Shown because whoever runs the old relay needs to know it is still
    /// needed.** Switched off before the end, it strands every device that has
    /// not come back yet. `None` after the end, whatever the parameters still say.
    #[serde(default)]
    pub relay_leaving: Option<RelayLeaving>,
    /// Devices in it the roster has evidence of having signed two histories.
    ///
    /// Its own field rather than a fault, because only the latest fault is
    /// shown and a detection would vanish behind a dial failure that repeats
    /// every minute.
    pub accused: Vec<Accused>,
    /// The other devices in it.
    pub peers: Vec<Peer>,
    /// The devices this device holds as revoked from it.
    ///
    /// What this device knows, not an account of the network: a revocation signed
    /// elsewhere that has not arrived is not here.
    pub revoked: Vec<Revoked>,
    /// Operations signed here that some member has not said it holds.
    ///
    /// Every revocation, then the others up to a bound, in the order they were
    /// signed. A bound that could hide a revocation would tell a person the
    /// stolen laptop is dealt with.
    pub waiting: Vec<Waiting>,
    /// How many further operations are waiting and not listed.
    pub waiting_unlisted: usize,
    /// What is wrong in it now: the latest fault, if recent.
    ///
    /// One, and no history. The history is the service's log; a surface needs
    /// to say whether something is wrong now, and a list of the last handful
    /// kept showing failures long since over.
    #[serde(default)]
    pub problem: Option<crate::node::Fault>,
    /// Why this device cannot confirm this network's roster, if it cannot.
    ///
    /// `None` is a roster confirmed within the time the network allows. Anything
    /// else means this device is refusing peers that are not administrators, and
    /// a surface that did not show it would leave a person watching their devices
    /// stop answering with nothing anywhere saying why.
    pub confirmation: Option<Unconfirmed>,
}

/// Why a device cannot confirm a network's roster.
///
/// Three states, because what a person does about them differs. Collapsing them
/// into one flag would leave the commonest of them — a network whose admins have
/// not signed anything — indistinguishable from a clock that is wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Unconfirmed {
    /// The network's window passed with nothing fresher accepted.
    Stale,
    /// No snapshot has ever been accepted for this network.
    NeverAttested,
    /// This device's clock moved, so elapsed time cannot be read from it.
    ClockMoved,
}

impl fmt::Display for Unconfirmed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Stale => "not confirmed within the time this network allows",
            Self::NeverAttested => "never confirmed: no snapshot has been accepted for it",
            Self::ClockMoved => "cannot be dated: this device's clock moved backwards",
        })
    }
}

impl Unconfirmed {
    /// What a person can do about it, in one sentence.
    ///
    /// **Reachability, not an errand.** It used to say *reach an administrator*,
    /// because only a person present at an admin device could make it sign the
    /// thing this one is waiting for. An admin's daemon now attests on its own,
    /// every few hours and whenever its heads move, so what is missing is not
    /// somebody's attention — it is a path between the two devices.
    #[must_use]
    pub const fn remedy(self) -> &'static str {
        match self {
            Self::Stale | Self::NeverAttested => {
                "an administrator's device has to become reachable from here — one attests on its own every few hours, and this device is waiting for the next. Until then it carries no traffic to devices that are not administrators."
            }
            Self::ClockMoved => {
                "check this device's clock, then let an administrator's device become reachable from here. Until then it carries no traffic to devices that are not administrators."
            }
        }
    }
}

impl Network {
    /// Whether anything signed here is waiting to reach another device in it.
    #[must_use]
    pub const fn has_unpropagated_work(&self) -> bool {
        !self.waiting.is_empty() || self.waiting_unlisted > 0
    }
}

/// A network directory this device could not carry, as the report describes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unusable {
    /// The directory it was found under.
    pub label: String,
    /// Why it could not be carried.
    pub cause: Trouble,
}

/// What stopped a network directory from being carried.
///
/// # Why this is a value and not a sentence
///
/// A sentence written here is a sentence in the daemon's language, and every
/// surface that draws it shows it in that language whatever the person reads. It
/// arrived on an Italian phone as an English paragraph in the middle of an
/// Italian screen. A value lets each surface say it in its own words, which is
/// what every other thing in this report already does.
///
/// # Why each one names a part and not a guess
///
/// The first version of this worked out what to say from **which files were
/// present** — identity there, roster there, therefore the roster must be the
/// trouble. It was wrong on the first real failure: the roster read and derived
/// perfectly, and what would not open was the identity, which a phone keeps in
/// its keystore and which exists as a file either way. A person was told their
/// network's history was damaged when it was intact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Trouble {
    /// No identity for this device is there. Nothing can prove membership.
    NoIdentity,
    /// The identity is there and will not open.
    ///
    /// On a phone it is sealed by the keystore, so this is what a lost or
    /// replaced keystore entry looks like. The roster may be perfectly good.
    IdentityWillNotOpen,
    /// An identity and no roster: nothing arrived, or what arrived was lost.
    NoRoster,
    /// The roster is there and this build will not load it.
    RosterRefused,
    /// The roster loads and describes no network this device belongs to.
    RosterProvesNothing,
    /// A folder under the networks directory that this daemon did not make.
    NotOurs,
    /// It holds a network and does not say who it is for.
    ///
    /// Reported rather than handed to whoever asks. A machine may hold networks
    /// for more than one person, so *whose* is not a question a daemon may
    /// answer by default.
    NoOwner,
    /// It is somebody else's.
    ///
    /// **Not** a fault, and named separately so that it never reads as one: the
    /// network is perfectly good and this person may not use it.
    SomebodyElses,
}

impl Trouble {
    /// Whether joining again is what fixes it.
    #[must_use]
    pub const fn rejoining_fixes_it(self) -> bool {
        matches!(self, Self::NoIdentity | Self::NoRoster | Self::IdentityWillNotOpen)
    }
}

impl fmt::Display for Trouble {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoIdentity => {
                "there is no identity for this device here, so nothing can prove membership of that network. Joining again is what gives this device a new one."
            }
            Self::IdentityWillNotOpen => {
                "this device's identity for that network is here and will not open. The roster may be perfectly good; what is lost is the key that proves this device is in it. Joining again is what gives this device a new one."
            }
            Self::NoRoster => {
                "this device has an identity for that network and no roster. Nothing arrived, or what arrived was lost. Joining again is what fixes it."
            }
            Self::RosterRefused => {
                "that network's roster is here and this version will not load it. It was written by a build whose rules differ, or the file has been damaged. Nothing has been removed."
            }
            Self::RosterProvesNothing => {
                "that network's roster is here and describes no network this device belongs to. Nothing has been removed."
            }
            Self::NotOurs => {
                "this folder is not one this daemon made. Nothing has been removed, and no network was lost."
            }
            Self::NoOwner => {
                "that network does not say who it is for. This machine can hold networks for more than one person, so it is not given to whoever asks first. Founding or joining it again records who it belongs to."
            }
            Self::SomebodyElses => {
                "that network belongs to somebody else on this machine. Nothing is wrong with it, and it is not yours to use."
            }
        })
    }
}

/// What the daemon answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// Whether the person this was answered for may stop the daemon.
    ///
    /// **So that a surface can offer only what would be allowed.** A tray that
    /// offered *Stop* to somebody who would be refused is a tray that teaches
    /// people to ignore it, and a surface guessing at the answer from its own
    /// token would be a second decision beside the one that counts. The daemon
    /// already identified whoever asked; this is that answer, handed back.
    ///
    /// True on a platform that draws no distinction between people: a phone has
    /// one person, and what they may do with their own daemon is everything.
    #[serde(default)]
    pub may_stop_the_daemon: bool,

    /// Whether they could stop it after confirming at the platform's own
    /// prompt: an administrator at an unelevated console.
    ///
    /// **For offering, never for deciding.** A tray runs unelevated, so without
    /// this it would never offer stopping to anybody. The stop it offers is
    /// asked again by an elevated process, and that is what the daemon decides.
    #[serde(default)]
    pub could_stop_the_daemon: bool,

    /// How many networks on this machine belong to somebody else.
    ///
    /// **A count, and nothing else about them.** A person who owns none must
    /// still be able to tell *«this machine holds nothing»* from *«this machine
    /// holds two networks and neither is yours»*, because the first is something
    /// to do and the second is somebody to ask. Their labels, addresses and
    /// devices are not this person's to read, and a label is often the most
    /// telling thing about a network there is.
    ///
    /// Always zero where the platform draws no distinction between people.
    #[serde(default)]
    pub elsewhere: usize,
    /// The networks this device holds, in the order it keeps them.
    ///
    /// Empty means this device holds none, which is a state and not a failure.
    /// It looks identical to a network that is down — no address, no peers,
    /// nothing installed — and the remedies are opposites: one is `up`, the
    /// other is founding or joining. A report that conflated them would send a
    /// person to the wrong command and tell them nothing about why it failed.
    pub networks: Vec<Network>,
    /// Network directories that are on disk and could not be carried.
    ///
    /// Reported rather than omitted. A daemon that silently held one fewer
    /// network than its owner believed would be the same class of quiet as one
    /// that replaced an identity it could not read.
    pub unusable: Vec<Unusable>,

    /// Something that just happened, when a command has news of its own.
    ///
    /// `None` for the ordinary reports, which describe a state rather than an
    /// event.
    pub note: Option<String>,

    /// Why this machine cannot hold an admin's key, if it cannot.
    ///
    /// A fact about the machine rather than about any one network, which is why
    /// it sits here and not beside each of them. A person reading a device that
    /// holds no network at all still needs it: it is the answer to why founding
    /// was refused.
    pub admin_refusal: Option<String>,
}

impl Report {
    /// The same report, with a line about what just happened.
    ///
    /// Used after an enrolment, where the interesting thing is not the state but
    /// what the other machine said about the network it was given.
    #[must_use]
    pub fn with_note(mut self, note: &str) -> Self {
        self.note = Some(note.to_owned());
        self
    }

    /// Whether this device holds a network at all.
    #[must_use]
    pub const fn holds_a_network(&self) -> bool {
        !self.networks.is_empty()
    }

    /// The one network this device holds, where it holds exactly one.
    ///
    /// For callers that predate a device being able to hold several and read the
    /// same either way.
    #[must_use]
    pub fn only(&self) -> Option<&Network> {
        match self.networks.as_slice() {
            [one] => Some(one),
            _ => None,
        }
    }
}

/// Which certificate a founding network pins for its relay.
///
/// Modelled rather than left as an `Option<Vec<u8>>` plus a flag, because the
/// third case is not a certificate at all: it is an instruction to go and get one
/// and show a person what came back. Only that case needs somebody to look at a
/// fingerprint before anything is signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Certificate {
    /// None pinned. A relay whose certificate verifies by ordinary means.
    None,
    /// These bytes, read from a file the person named.
    Given(Vec<u8>),
    /// Whatever the relay presents — to be shown to a person before it is pinned.
    ///
    /// Nothing has vouched for it: anyone in the path could have answered. So the
    /// daemon fetches, reports the fingerprint, and signs nothing until somebody
    /// confirms it against the relay host.
    FromTheRelay,
}

/// A signing key the daemon needs and cannot make.
///
/// Inert, like [`SignaturesWanted`]: it names a key that does not exist yet and
/// grants nothing. `network` is here because the key store's own prompt names
/// it — that prompt is fixed when the key is made and cannot name an act, which
/// is why there is one key per network and not one per act.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyWanted {
    /// What the answer must carry back, so one answer completes one act.
    pub id: String,
    /// What to call the key in the key store.
    pub name: String,
    /// The network it is for, which is what a person will be shown — empty
    /// while it is being joined, when it has no name here yet.
    pub network: String,
}

/// Everything one act needs signed by a key held outside this process.
///
/// Carried to whichever component can reach that key — on Windows and Linux the
/// command line, running as the person, because the key store (or the TPM, or
/// the passphrase) will only answer there.
///
/// **A batch.** An act can need several signatures — an operation, and the
/// snapshot over the roster once it is in; a revocation, and the admission that
/// replaces it — and none depends on another's signature. So all of them are
/// prepared before any is made, shown to the person together, authorised once,
/// and answered in one [`Command::Signed`]. The daemon applies them together or
/// not at all.
///
/// It is inert. Holding one grants nothing: the bytes are public, the key is
/// named and not given, and answering with a signature over anything else is
/// refused by the side that made the request. What it is *for* is the person:
/// each item's [`ToSign::payload`] is the act itself, so the component that asks
/// them can read what is about to happen out of the bytes that will happen,
/// rather than out of a description sent beside them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignaturesWanted {
    /// Which pending batch this is, so the answer can be matched to it.
    ///
    /// Single use. An answer to an id that has been answered, or that was never
    /// issued, is refused.
    pub id: String,
    /// The name the key store knows the signing key by. One key signs the whole
    /// batch.
    pub key: String,
    /// What this machine calls the network whose key this is.
    ///
    /// **Empty while the network is being joined**: it has no name here until it
    /// arrives, and a surface says *the network being joined* instead.
    ///
    /// **Whose key, not what act.** It is here so a person holding several
    /// networks knows which passphrase is being asked for; it says nothing about
    /// what is being signed, which is read from the items. A daemon that lied
    /// about it could at most have a person type another network's passphrase,
    /// which unlocks nothing and signs nothing. Where the person named the
    /// network on the command line, the command line checks this against that.
    pub network: String,
    /// What is to be signed, in the order it takes effect.
    pub items: Vec<ToSign>,
}

/// The most items one batch may hold.
///
/// The largest act there is — a revocation, the admission replacing it, and the
/// snapshot over both — is three. One more is room, not an invitation: a batch
/// is shown to a person whole, and a list nobody reads is not consent.
pub const MOST_IN_A_BATCH: usize = 4;

/// One thing in a batch to be signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToSign {
    /// What the signature will become.
    pub kind: SigningKind,
    /// The exact bytes to sign — no more, and nothing derived from them.
    pub message: Vec<u8>,
    /// The artifact those bytes commit to, for a person to be shown.
    ///
    /// Empty for a proof of possession, whose signature is the whole artifact and
    /// which is not an administrative act a person authorises separately.
    pub payload: Vec<u8>,
}

impl ToSign {
    /// The item a prepared request becomes on the wire.
    #[must_use]
    pub fn from_request(request: &identity::detached::SigningRequest) -> Self {
        Self {
            kind: request.kind().into(),
            message: request.message().to_vec(),
            payload: request.payload().to_vec(),
        }
    }
}

/// What a pending signature will become once it is made.
///
/// A separate type from `identity`'s, deliberately: this one crosses a process
/// boundary and has to encode, and `identity` has no business gaining a
/// serialisation format because Windows needed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SigningKind {
    /// A roster operation — the administrative acts.
    Operation,
    /// A roster snapshot.
    Snapshot,
    /// A joining device's proof that it holds the key it presented.
    Possession,
}

impl From<identity::detached::RequestKind> for SigningKind {
    fn from(kind: identity::detached::RequestKind) -> Self {
        match kind {
            identity::detached::RequestKind::Operation => Self::Operation,
            identity::detached::RequestKind::Snapshot => Self::Snapshot,
            identity::detached::RequestKind::Possession => Self::Possession,
        }
    }
}

/// Who asked, as far as the platform can tell.
///
/// The portable half **never interprets one of these**. It stores what the
/// platform gave it and asks the platform whether two are the same person. A
/// security identifier on Windows means nothing on a phone, and a portable half
/// that understood one would be a portable half with a Windows assumption in it.
///
/// It is also never taken from anything a client sent. A caller that could say
/// who it is, is a caller that can say it is somebody else — the platform reads
/// it from the channel and hands it over, and nothing on the wire carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Caller {
    /// A platform that does not distinguish between people, and says so.
    ///
    /// A phone is one: the device is the person's, there is no second account,
    /// and inventing an identifier would be inventing a distinction that does
    /// not exist there.
    Unattributed,
    /// Somebody the platform identified, by a name only it reads.
    Identified {
        /// What the platform calls them. Compared, never interpreted.
        name: String,
        /// Whether they may act on the **machine** and not only on their own
        /// things.
        ///
        /// Deliberately not called *administrator*: that is one platform's word
        /// for it, and the portable half asking whether somebody is a Windows
        /// administrator would be the portable half knowing about Windows. What
        /// it needs is the distinction, and the platform draws it.
        privileged: bool,
        /// Whether they are not privileged now and could be, by confirming it —
        /// an administrator at an unelevated console, who is one prompt away.
        ///
        /// **Decides nothing.** A surface uses it to offer an act that it will
        /// then ask for again, from a process that did confirm; this caller is
        /// still refused anything [`Self::may_act_on_the_machine`] would refuse.
        could_be_privileged: bool,
    },
}

impl Caller {
    /// Whether this caller could act on the machine after confirming it at the
    /// platform's own prompt. For offering, never for deciding.
    #[must_use]
    pub const fn could_act_on_the_machine(&self) -> bool {
        matches!(self, Self::Identified { could_be_privileged: true, .. })
    }

    /// Whether this caller may act on the machine rather than on their own
    /// things only.
    ///
    /// False where the platform draws no distinction: a phone has one person,
    /// and a *privileged* one there would be a distinction with nothing on the
    /// other side of it.
    #[must_use]
    pub const fn may_act_on_the_machine(&self) -> bool {
        matches!(self, Self::Identified { privileged: true, .. })
    }

    /// The name this caller is known by, where the platform gives one.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Unattributed => None,
            Self::Identified { name, .. } => Some(name),
        }
    }

    /// Whether this caller is the one a network was recorded for.
    ///
    /// A network with no owner recorded belongs to nobody, and answering *yes*
    /// for it would hand it to whoever asked first. That is why it is a refusal
    /// and not a default.
    #[must_use]
    pub fn is(&self, owner: Option<&str>) -> bool {
        match (self, owner) {
            // Where the platform draws no distinction, there is nobody for a
            // network to belong to and nothing to check.
            (Self::Unattributed, None) => true,
            (Self::Identified { name, .. }, Some(owner)) => name == owner,
            // An owned network on a platform that cannot say who is asking, and
            // an unowned one where it can: both are a state nothing produces,
            // and guessing which way to resolve them is how a network ends up
            // belonging to whoever asked.
            _ => false,
        }
    }
}

/// The word every refusal for want of authority carries.
///
/// **So that the two refusals cannot be confused.** A person told *«that is not
/// allowed»* with no more has to guess whether they are being told about this
/// machine or about the network, and the two have entirely different remedies:
/// one is an account, the other is an admin. A refusal from here says
/// authorisation and never says membership.
pub const AUTHORISATION: &str = "not authorised";

/// What a command needs of whoever asks it.
///
/// **The whole table, in one place and as a value.** Scattered through the
/// handler, each arm would be a decision somebody could forget to make — and the
/// arm that forgot would be the one that let anybody through, because doing
/// nothing is doing nothing. Here, a command with no entry does not compile.
///
/// It says nothing about *what comes back*. Reading is allowed to everybody
/// because what a person is shown is bounded by what is theirs, which is a
/// property of the report and not of this.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Needs {
    /// Anybody the channel could identify.
    ///
    /// Founding and joining make a network that has no owner yet, so there is
    /// nobody for them to need; reading is bounded by what the reader may see.
    Nobody,
    /// The person the named network belongs to.
    ///
    /// `None` is *the only one there is*, resolved where the command is
    /// answered, because a device holding one network should not have to name it.
    TheOwnerOf(Option<String>),
    /// The person whose act is in flight.
    ///
    /// Confirming, abandoning and signing act on something already begun, and it
    /// is begun by somebody. A second person completing another's enrolment is
    /// the hole this closes, and it is the same hole as the one
    /// `Pending::Founding` carries an owner to close.
    WhoeverBeganTheAct,
    /// Somebody who may act on the machine.
    TheMachine,
    /// The person the named network belongs to, acting as an administrator.
    ///
    /// Both, and each checked: an act on a network's behalf that changes the
    /// machine itself — its firewall — is neither the owner's alone nor the
    /// administrator's alone.
    TheOwnerOfAsAdministrator(Option<String>),
}

impl Command {
    /// Who may ask this.
    ///
    /// Exhaustive by construction: this matches on every variant with no
    /// wildcard, so a command added without an entry here is a build failure
    /// rather than a command anybody may ask.
    #[must_use]
    pub fn needs(&self) -> Needs {
        match self {
            // Reading. What comes back is bounded by what the reader may see.
            Self::Status | Self::Waiting => Needs::Nobody,
            Self::Peers { network } | Self::Address { network } => match network {
                // Naming none is asking about everything this person holds,
                // which is the same question as `Status`.
                None => Needs::Nobody,
                Some(_) => Needs::TheOwnerOf(network.clone()),
            },

            // Making a network. There is nobody for it to belong to yet: the
            // owner is recorded as it comes into being, by whoever asked.
            Self::Found { .. } | Self::Join { .. } => Needs::Nobody,

            // Changing a tunnel, or acting on a roster.
            Self::Up { network }
            | Self::Down { network }
            | Self::Admit { network, .. }
            | Self::Revoke { network, .. }
            | Self::Rename { network, .. }
            | Self::ChangeRelay { network, .. }
            | Self::ChangeRendezvous { network, .. } => Needs::TheOwnerOf(network.clone()),
            Self::Expose { network, .. } | Self::Unexpose { network, .. } => {
                Needs::TheOwnerOfAsAdministrator(network.clone())
            }
            Self::Exposed { network } => match network {
                // All of this person's: answered from what they own, as `Status` is.
                None => Needs::Nobody,
                Some(_) => Needs::TheOwnerOf(network.clone()),
            },
            Self::Forget { label, .. } => Needs::TheOwnerOf(Some(label.clone())),

            // Finishing something already begun.
            Self::Confirm
            | Self::Replace
            | Self::ConfirmJoin { .. }
            | Self::Abandon
            | Self::Signed { .. }
            | Self::KeyMade { .. }
            | Self::NotSigned { .. } => Needs::WhoeverBeganTheAct,

            // The machine's.
            Self::Stop | Self::TakeOwnership { .. } => Needs::TheMachine,
        }
    }
}

/// What a person asked for.
///
/// Not `Copy` any more: enrolment carries a payload, and a command that had to
/// be cheap to copy would have to keep it somewhere else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Command {
    /// Report the state of every network this device holds.
    Status,
    /// Bring a network's tunnel up.
    Up {
        /// Which network, or `None` when only one could be meant.
        network: Option<String>,
    },
    /// Take a network's tunnel down.
    Down {
        /// Which network, or `None` when only one could be meant.
        network: Option<String>,
    },
    /// List the other devices in a network.
    Peers {
        /// Which network, or `None` when only one could be meant.
        network: Option<String>,
    },
    /// Show this device's own overlay address in a network.
    Address {
        /// Which network, or `None` when only one could be meant.
        network: Option<String>,
    },
    /// Stop the daemon, taking every network down.
    Stop,

    /// Begin admitting the device that produced this payload.
    ///
    /// Opens the exchange, checks that the device holds both of the keys it
    /// presented, and works out the confirmation code — and stops there. Nothing
    /// is signed, because a person has not compared two screens yet.
    Admit {
        /// Which network to admit the device into, or `None` when only one could
        /// be meant.
        network: Option<String>,
        /// The joining payload, as the device printed it.
        payload: String,
    },

    /// Confirm whatever is waiting on this device's own person.
    ///
    /// Two things wait that way: an **admission**, after a person has looked at
    /// the device being enrolled and seen it say the code was accepted; and a
    /// **founding**, after a person has checked a relay certificate's
    /// fingerprint. Neither carries a value, because in both the person is
    /// answering a question about something already on screen.
    ///
    /// A **join** is the one that does not belong here: what its person supplies
    /// is digits read off another machine. That is [`Self::ConfirmJoin`].
    Confirm,

    /// Confirm an admission **and revoke the device already holding that name**.
    ///
    /// The other answer to the question [`Outcome::Admitting::taken`] asks.
    /// [`Self::Confirm`] admits under a name no device holds; this one keeps the
    /// name and expels whoever had it.
    ///
    /// It is a revocation, and a revocation is definitive: the device it names
    /// never returns to the network. A surface asks before sending it, and shows
    /// the identifier it falls on — a name is not an identity, and this decision
    /// is being taken on the strength of one.
    Replace,

    /// Confirm a join with the digits a person read off the admitting machine.
    ///
    /// Sent by the **joining** side. The code travels here, from the person, and
    /// is compared with the one this device derived. A command carrying no code
    /// would leave the daemon comparing its own answer with itself — which is
    /// what this replaces, and what made the check always pass.
    ConfirmJoin {
        /// The six digits a person typed.
        code: String,
    },

    /// Drop an enrolment that is waiting, leaving both machines as they were.
    Abandon,

    /// Start waiting to be given a network.
    ///
    /// Through the daemon for the same reason founding is: the roster that
    /// arrives has to be the one the daemon is using. A device that joined in
    /// another process would hold a network its own daemon could not see until it
    /// restarted, which is the restart this removes.
    Join {
        /// Where to be reachable while waiting.
        relay: String,
        /// The name this device proposes for itself.
        name: String,
    },

    /// Remove a network from this device, carried or not.
    ///
    /// It discards the network's directory and **every key this device keeps
    /// for it, wherever it is kept**. A device cannot rejoin a network under an
    /// identity it has thrown away, so a surface asks first. It is local: the
    /// network is told nothing, and the other devices go on listing this one
    /// until an administrator revokes it.
    ///
    /// Refused while an enrolment for that network is waiting for a person, and
    /// refused with [`Outcome::OnlyAdmin`] when this device is the network's only
    /// admin and `last_admin` is not set.
    Forget {
        /// The network, by the name it is reported under.
        label: String,
        /// That the person was told this device is the network's only admin,
        /// and that nobody will be able to admit or revoke anything in it
        /// afterwards — and said yes. Absent reads as `false`.
        #[serde(default)]
        last_admin: bool,
    },

    /// Ask what a waiting enrolment has got to.
    ///
    /// A join has two pauses in it — carrying the payload to an admin, and
    /// comparing six digits — and the control channel is one request and one
    /// answer. So the command line asks, rather than being told.
    ///
    /// It also answers the other question a surface has: **is anything held at
    /// all**. The daemon keeps one pending, and it is what refuses the next
    /// enrolment, so a surface whose own screens have ended needs to know whether
    /// the daemon still holds something before it offers to start another.
    /// [`Outcome::Done`] means nothing is held; every other answer names what is.
    /// A failure that is still held answers [`Outcome::Failed`] — which is why
    /// "nothing" cannot answer that too, however it is worded.
    Waiting,

    /// Create a network on this device.
    ///
    /// Through the daemon rather than in the process that typed it: the daemon
    /// holds the roster, and an operation appended to the log by another process
    /// is invisible to it until it restarts. That restart is what this exists to
    /// remove.
    Found {
        /// What this device will call the network it is about to create.
        ///
        /// Local to this machine: it names the folder the network is kept in and
        /// nothing the network itself agrees on. It is supplied up front because
        /// the network's own id is the id of the operation that founds it, which
        /// cannot be known before the keys that sign it exist — and those keys
        /// need somewhere to be written.
        label: String,
        /// The name this device takes in its own network.
        name: String,
        /// The DNS suffix every name in the network sits under.
        suffix: String,
        /// The relay, if the network has one.
        relay: Option<String>,
        /// The rendezvous, if the network has one.
        rendezvous: Option<String>,
        /// Which certificate, if any, the network pins for its relay.
        certificate: Certificate,
        /// The IPv4 range every device of the network derives its IPv4 address
        /// in, as `a.b.c.d/len`, or `None` for the default.
        ///
        /// Text rather than a parsed range so a surface can hand over what a
        /// person typed and have the refusal come back in the daemon's words,
        /// before anything is signed.
        ipv4_range: Option<String>,
    },

    /// Expel a device from the network.
    ///
    /// Named exactly as the roster names it, and with a reason, because the log
    /// is append-only: a revocation made by mistake cannot be withdrawn, only
    /// followed by admitting the device afresh under a new identity.
    Revoke {
        /// Which network to expel the device from, or `None` when only one could
        /// be meant.
        network: Option<String>,
        /// The device, by the name it answers to or by its id.
        target: Target,
        /// Why, as the person wrote it.
        reason: String,
    },

    /// Give a device a new name.
    ///
    /// Named as [`Command::Revoke`] names it, exactly, by name or by id. The new
    /// name is checked by the daemon, which lowers it and refuses one a resolver
    /// could not answer.
    Rename {
        /// Which network the device is in, or `None` when only one could be meant.
        network: Option<String>,
        /// The device, by the name it answers to or by its id.
        target: Target,
        /// The name it is to answer to, as the person typed it.
        name: String,
    },

    /// The signature a previous answer asked for.
    ///
    /// Not a command a person types. It continues an act the daemon began and
    /// could not finish, in the same way [`Command::Confirm`] continues an
    /// admission: the daemon holds what it prepared, and this brings back the one
    /// thing it cannot produce.
    Signed {
        /// The pending batch being answered, from [`SignaturesWanted::id`].
        id: String,
        /// One signature per item, in the items' order, each over that item's
        /// message in the key store's own encoding.
        signatures: Vec<Vec<u8>>,
    },

    /// Take a network that belongs to somebody else on this machine.
    ///
    /// A privileged act, and a visible one. It is how a network survives the
    /// account that made it being deleted — and because it is also how one
    /// person takes another's network, what it did is recorded rather than left
    /// to look as though it had always been theirs.
    TakeOwnership {
        /// Which network, or `None` when only one could be meant.
        network: Option<String>,
    },

    /// Move a network to another relay.
    ///
    /// Signed like every administrative act, and changes every device in the
    /// network. By default a transition: everybody stays on the old relay until
    /// one freshness window has passed, so a device switched off now can still
    /// find the network when it comes back. `immediately` moves everybody at once
    /// and loses whoever is switched off — a surface asks a person to confirm that
    /// cost before sending it.
    ChangeRelay {
        /// Which network, or `None` when only one could be meant.
        network: Option<String>,
        /// The relay to move to.
        relay: String,
        /// Whether to fetch its certificate, show it, and pin it once confirmed.
        /// `false` for a relay with a publicly trusted certificate that renews.
        pin: bool,
        /// Whether to move at once, with no transition.
        immediately: bool,
    },

    /// Set or remove a network's rendezvous, as its admin: a signed change of
    /// its parameters, as a relay change is.
    ChangeRendezvous {
        /// Which network, or `None` when only one could be meant.
        network: Option<String>,
        /// The rendezvous, an HTTPS address, or `None` to remove it.
        rendezvous: Option<String>,
    },

    /// Open a port on this machine to one network, and to nothing else (F-11).
    ///
    /// The machine's firewall, so it is an administrator's act as well as the
    /// network's owner's: a person who is not an administrator must not be able
    /// to open the machine's own services to their devices.
    Expose {
        /// Which network. Always named: a port opened to the wrong network is a
        /// worse mistake than a word typed twice.
        network: Option<String>,
        /// The protocol.
        protocol: crate::exposing::Protocol,
        /// The port.
        port: u16,
    },

    /// Close a port [`Command::Expose`] opened.
    Unexpose {
        /// Which network.
        network: Option<String>,
        /// The protocol.
        protocol: crate::exposing::Protocol,
        /// The port.
        port: u16,
    },

    /// What is open, to one network or to every network this person holds.
    Exposed {
        /// Which network, or `None` for all of this person's.
        network: Option<String>,
    },

    /// The signing key asked for by [`Outcome::NeedsKey`] now exists.
    ///
    /// It carries the key's public half only as a cross-check: the daemon knows
    /// the name it asked for and reads the key itself, because a public key
    /// arriving over the channel is a claim, and building an identity around a
    /// claim would let whoever answered choose the key a network is founded on.
    KeyMade {
        /// The act being answered, from [`KeyWanted::id`].
        id: String,
        /// The key's public half, as the roster spells one.
        public: Vec<u8>,
    },

    /// The signature a previous answer asked for will not be coming.
    ///
    /// A person declined, or the prompt timed out. Sent so the daemon can drop
    /// what it was holding at once rather than keeping a half-finished act alive
    /// until it expires.
    NotSigned {
        /// The pending request being abandoned.
        id: String,
    },
}

/// How a person named the device to revoke.
///
/// Two variants rather than one string that might look like an id, because a
/// device may be *named* `0a1b-2c3d-4e5f-6a7b`. Which one a person meant is said
/// by the flag they typed, not guessed from the shape of the word.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    /// Exactly the name the roster gives it.
    Name(String),
    /// Its short id, as the report shows it.
    Id(String),
}

impl Command {
    /// Every command that exists.
    ///
    /// Enrolment is not among them. `enrollment-flow` defines the invite token
    /// and the QR payload, and a `join` here that accepted something and failed
    /// would teach a person a workflow that is not the one they will end up
    /// using.
    pub const ALL: &'static [(&'static str, bool)] = &[
        ("status", false),
        ("up", true),
        ("down", true),
        ("peers", true),
        ("address", true),
        ("stop", false),
        // How a network survives the account that made it being deleted. A
        // command nothing could ask for would be a recovery path that exists
        // only in the tests — found by writing the verification step for it and
        // discovering the word did not work.
        ("takeownership", true),
    ];

    /// The usage line for forgetting a network this device cannot carry.
    ///
    /// Listed apart from `ALL` for the same reason revoking is: it names
    /// something, and `ALL` is the commands that are a single word.
    pub const FORGET_USAGE: &'static str = "peerfectly forget <the name it is reported under>";

    /// The usage line for revoking, listed with the commands rather than among
    /// them: it takes arguments, and `ALL` is the ones that are a single word.
    pub const REVOKE_USAGE: &'static str = "peerfectly revoke <name> <reason...> [--network N]\n       \
                                             peerfectly revoke --id <id> <reason...> [--network N]";

    /// The usage line for renaming, listed with the commands for the same reason
    /// as revoking: it takes arguments.
    pub const RENAME_USAGE: &'static str = "peerfectly rename <name> <new name> [--network N]\n       \
                                             peerfectly rename --id <id> <new name> [--network N]";

    /// The usage line for moving a network to another relay.
    pub const RELAY_USAGE: &'static str =
        "peerfectly relay <address> [--network N] [--no-relay-cert] [--now]";

    /// The usage line for setting or removing a network's rendezvous.
    pub const RENDEZVOUS_USAGE: &'static str =
        "peerfectly rendezvous <https address> | --none [--network N]";

    /// The usage lines for exposing a service to one network.
    pub const EXPOSE_USAGE: &'static str = "peerfectly expose <network> tcp|udp <port>\n       \
                                             peerfectly unexpose <network> tcp|udp <port>\n       \
                                             peerfectly exposed [network]";

    /// Reads `expose` or `unexpose` and the words after it.
    ///
    /// The network is always named, never inferred: a port opened to the wrong
    /// network is a worse mistake than typing a name.
    ///
    /// # Errors
    ///
    /// When a word is missing, the protocol is not `tcp` or `udp`, or the port
    /// is not a number from 1 to 65535.
    pub fn exposure(verb: &str, words: &[String]) -> core::result::Result<Self, String> {
        let usage = || format!("usage: {}", Self::EXPOSE_USAGE);
        let [network, protocol, port] = words else { return Err(usage()) };
        if network.is_empty() || network.starts_with("--") {
            return Err(usage());
        }
        let protocol = crate::exposing::Protocol::parse(protocol).ok_or_else(|| {
            format!("`{}` is not a protocol: tcp or udp. {}", shown(protocol), usage())
        })?;
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| format!("`{}` is not a port from 1 to 65535.", shown(port)))?;
        let network = Some(network.clone());
        match verb {
            "expose" => Ok(Self::Expose { network, protocol, port }),
            "unexpose" => Ok(Self::Unexpose { network, protocol, port }),
            _ => Err(usage()),
        }
    }

    /// Reads a relay change from the words after `relay`.
    ///
    /// Here rather than in the command line, for the reason revoking's is: it
    /// decides what reaches the daemon, and what reaches it is signed.
    ///
    /// # Errors
    ///
    /// When no address is given, or a flag is not one this knows.
    pub fn relay_change(words: &[String]) -> core::result::Result<Self, String> {
        let usage = || format!("usage: {}", Self::RELAY_USAGE);
        let mut relay = None;
        let mut network = None;
        let mut pin = true;
        let mut immediately = false;
        let mut rest = words.iter();
        while let Some(word) = rest.next() {
            match word.as_str() {
                "--network" => network = Some(rest.next().ok_or_else(usage)?.clone()),
                "--no-relay-cert" => pin = false,
                "--now" => immediately = true,
                flag if flag.starts_with("--") => return Err(usage()),
                // An empty word is not an address: taken as one, it would be a
                // move to nowhere, found out only once a certificate had been
                // asked for.
                address if relay.is_none() && !address.is_empty() => {
                    relay = Some(address.to_owned());
                }
                _ => return Err(usage()),
            }
        }
        Ok(Self::ChangeRelay { network, relay: relay.ok_or_else(usage)?, pin, immediately })
    }

    /// Reads a rendezvous change from the words after `rendezvous`.
    ///
    /// # Errors
    ///
    /// When neither an address nor `--none` is given, both are, a flag is not
    /// one this knows, or the address is not HTTPS.
    pub fn rendezvous_change(words: &[String]) -> core::result::Result<Self, String> {
        let usage = || format!("usage: {}", Self::RENDEZVOUS_USAGE);
        let mut address = None;
        let mut none = false;
        let mut network = None;
        let mut rest = words.iter();
        while let Some(word) = rest.next() {
            match word.as_str() {
                "--network" => network = Some(rest.next().ok_or_else(usage)?.clone()),
                "--none" => none = true,
                flag if flag.starts_with("--") => return Err(usage()),
                given if address.is_none() && !given.is_empty() => {
                    address = Some(given.to_owned());
                }
                _ => return Err(usage()),
            }
        }
        match (address, none) {
            (Some(address), false) => {
                Self::rendezvous_address(&address)?;
                Ok(Self::ChangeRendezvous { network, rendezvous: Some(address) })
            }
            (None, true) => Ok(Self::ChangeRendezvous { network, rendezvous: None }),
            _ => Err(usage()),
        }
    }

    /// Whether an address can be a rendezvous: HTTPS, with a host.
    ///
    /// Checked by the command line and again by the daemon, which does not
    /// trust whoever sent the command to have checked it.
    ///
    /// # Errors
    ///
    /// When it does not parse, is not `https`, or names no host.
    pub fn rendezvous_address(address: &str) -> core::result::Result<(), String> {
        let parsed = url::Url::parse(address)
            .map_err(|cause| format!("`{}` is not an address: {cause}", shown(address)))?;
        if parsed.scheme() != "https" || parsed.host().is_none() {
            return Err(format!(
                "`{}` is not an HTTPS address: a rendezvous is only spoken to over TLS",
                shown(address)
            ));
        }
        Ok(())
    }

    /// Reads a revocation from the words after `revoke`.
    ///
    /// Here rather than in the command line, which is a binary with no tests: this
    /// is the half that decides what reaches the daemon, and what reaches it is
    /// signed into an append-only log.
    ///
    /// # Errors
    ///
    /// When no device is named, when `--id` is given nothing, or when there is no
    /// reason.
    pub fn revocation(words: &[String]) -> core::result::Result<Self, String> {
        let usage = || format!("usage: {}", Self::REVOKE_USAGE);
        let (target, after) = match words.first().map(String::as_str) {
            Some("--id") => {
                let id = words.get(1).ok_or_else(usage)?;
                (Target::Id(id.clone()), 2)
            }
            Some(name) => (Target::Name(name.to_owned()), 1),
            None => return Err(usage()),
        };

        // Everything after the device and before the first option. The reason is
        // signed into the roster and kept for whoever reads it later, so
        // `--network casa` landing inside it would be a permanent record of a
        // typed flag — in an append-only log, where it cannot be tidied afterwards.
        let reason = words
            .get(after..)
            .unwrap_or(&[])
            .iter()
            .take_while(|word| !word.starts_with("--"))
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        if reason.trim().is_empty() {
            return Err(format!(
                "a revocation needs a reason: the roster keeps it for whoever reads it later.\n{}",
                usage()
            ));
        }

        let network = words
            .iter()
            .position(|word| word == "--network")
            .and_then(|at| words.get(at.checked_add(1)?))
            .cloned();
        Ok(Self::Revoke { network, target, reason })
    }

    /// Reads a renaming from the words after `rename`.
    ///
    /// The new name is passed on as typed: whether it can be a device's name is
    /// the daemon's to say, so the phone hears the same answer.
    ///
    /// # Errors
    ///
    /// When no device is named, when `--id` is given nothing, or when there is no
    /// new name, or more than one word for it.
    pub fn renaming(words: &[String]) -> core::result::Result<Self, String> {
        let usage = || format!("usage: {}", Self::RENAME_USAGE);
        let (target, after) = match words.first().map(String::as_str) {
            Some("--id") => {
                let id = words.get(1).ok_or_else(usage)?;
                (Target::Id(id.clone()), 2)
            }
            Some(name) => (Target::Name(name.to_owned()), 1),
            None => return Err(usage()),
        };
        let given: Vec<&String> = words
            .get(after..)
            .unwrap_or(&[])
            .iter()
            .take_while(|word| !word.starts_with("--"))
            .collect();
        let [name] = given.as_slice() else {
            return Err(format!(
                "a device's new name is one word: letters, digits and hyphens.\n{}",
                usage()
            ));
        };
        let network = words
            .iter()
            .position(|word| word == "--network")
            .and_then(|at| words.get(at.checked_add(1)?))
            .cloned();
        Ok(Self::Rename { network, target, name: (*name).clone() })
    }

    /// Reads a command name.
    ///
    /// # Errors
    ///
    /// When no such command exists.
    pub fn parse(name: &str, network: Option<String>) -> core::result::Result<Self, Unknown> {
        match name {
            "status" => Ok(Self::Status),
            "up" => Ok(Self::Up { network }),
            "down" => Ok(Self::Down { network }),
            "peers" => Ok(Self::Peers { network }),
            "address" => Ok(Self::Address { network }),
            "stop" => Ok(Self::Stop),
            "takeownership" => Ok(Self::TakeOwnership { network }),
            _ => Err(Unknown { name: name.to_owned() }),
        }
    }

    /// Whether a word names a command that acts on one network.
    ///
    /// Used by the command line to know whether a second word is a network's
    /// name or a mistake.
    #[must_use]
    pub fn takes_a_network(name: &str) -> bool {
        Self::ALL.iter().any(|(word, takes)| *word == name && *takes)
    }

    /// Whether this command changes the machine, and so needs Administrator.
    ///
    /// **It was aspirational and is not any more.** While the daemon created its
    /// channel with a default descriptor, a medium-integrity process could not
    /// write to a pipe a high-integrity one had made, so *every* command needed
    /// an elevated console whatever this said. The channel carries an explicit
    /// descriptor now, with an integrity label an ordinary process may write to,
    /// and reading state needs no elevation at all.
    ///
    /// **It is not the authorisation table**, and must not be read as one. That
    /// is [`Self::needs`], which is decided by the daemon against the caller it
    /// identified. This is a hint the command line prints beside a word, so that
    /// somebody reading the usage knows which ones will want an elevated console
    /// — and where the two ever disagree, the daemon's answer is the one that
    /// happens.
    #[must_use]
    pub const fn needs_administrator(&self) -> bool {
        matches!(
            self,
            Self::Up { .. }
                | Self::Down { .. }
                | Self::Revoke { .. }
                | Self::Rename { .. }
                | Self::Found { .. }
                | Self::Join { .. }
                // The two that are the machine's rather than a network's.
                | Self::Stop
                | Self::TakeOwnership { .. }
                | Self::Expose { .. }
                | Self::Unexpose { .. }
        )
    }

    /// Whether this command is part of enrolling a device.
    ///
    /// These three are not in [`Self::ALL`]: two of them are meaningless typed
    /// on their own, and the first carries a payload, so a person reaches them
    /// through `peerfectly admit` rather than by naming them.
    #[must_use]
    pub const fn is_enrolment(&self) -> bool {
        matches!(
            self,
            Self::Admit { .. } | Self::Confirm | Self::Abandon | Self::Join { .. } | Self::Waiting
        )
    }

    /// The word that invokes it.
    ///
    /// The empty string for a command a person does not reach by typing one
    /// word: the enrolment ones carry a payload, and founding and joining carry
    /// more than a person would type as a single token.
    #[must_use]
    pub const fn word(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Up { .. } => "up",
            Self::Down { .. } => "down",
            Self::Peers { .. } => "peers",
            Self::Address { .. } => "address",
            Self::Stop => "stop",
            Self::TakeOwnership { .. } => "takeownership",
            _ => "",
        }
    }

    /// What the service's log records of this command: a word, and the network
    /// it names. `None` for a read, which changes nothing and which a tray asks
    /// every two seconds.
    ///
    /// **Chosen fields, never the command.** Several carry an enrolment payload,
    /// a confirmation code, a signature or a public key, and none of those
    /// belongs in a log every administrator of the machine can read. Written out
    /// arm by arm so that a new command has to decide.
    #[must_use]
    pub fn logged(&self) -> Option<(&'static str, Option<&str>)> {
        let (word, network) = match self {
            Self::Status
            | Self::Peers { .. }
            | Self::Address { .. }
            | Self::Waiting
            | Self::Exposed { .. } => return None,
            Self::Up { network } => ("up", network.as_deref()),
            Self::Down { network } => ("down", network.as_deref()),
            Self::Stop => ("stop", None),
            Self::Admit { network, payload: _ } => ("admit", network.as_deref()),
            Self::Confirm => ("confirm", None),
            Self::Replace => ("replace", None),
            Self::ConfirmJoin { code: _ } => ("confirm join", None),
            Self::Abandon => ("abandon", None),
            Self::Join { .. } => ("join", None),
            Self::Forget { label, .. } => ("forget", Some(label.as_str())),
            Self::Found { label, .. } => ("found", Some(label.as_str())),
            Self::Revoke { network, .. } => ("revoke", network.as_deref()),
            Self::Rename { network, .. } => ("rename", network.as_deref()),
            Self::Signed { .. } => ("signed", None),
            Self::TakeOwnership { network } => ("takeownership", network.as_deref()),
            Self::ChangeRelay { network, .. } => ("relay", network.as_deref()),
            Self::ChangeRendezvous { network, .. } => ("rendezvous", network.as_deref()),
            Self::Expose { network, .. } => ("expose", network.as_deref()),
            Self::Unexpose { network, .. } => ("unexpose", network.as_deref()),
            Self::KeyMade { .. } => ("key made", None),
            Self::NotSigned { .. } => ("not signed", None),
        };
        Some((word, network))
    }
}

impl Outcome {
    /// What kind of answer this is, for the service's log. The kind only: a
    /// report, a code or a payload is not the log's.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Reported(_) => "reported",
            Self::Done => "done",
            Self::Admitting { .. } => "admitting",
            Self::Enrolling => "enrolling",
            Self::Joining { .. } => "joining",
            Self::Adopted { .. } => "adopted",
            Self::Pinning { .. } => "pinning",
            Self::NeedsSignatures(_) => "needs signatures",
            Self::Declined { .. } => "declined",
            Self::NeedsKey(_) => "needs a key",
            Self::NotAllowed { .. } => "not allowed",
            Self::OnlyAdmin { .. } => "only admin",
            Self::Exposed { .. } => "exposed",
            Self::Failed { .. } => "failed",
        }
    }

    /// A refusal for want of authority.
    ///
    /// Its own answer rather than a failure: nothing went wrong, and nothing
    /// about the network was consulted.
    #[must_use]
    pub fn not_allowed(message: String) -> Self {
        Self::NotAllowed { message }
    }

    /// The outcome for a refusal that came back as words.
    ///
    /// Founding, admitting, joining and revoking report their refusals as text,
    /// and one of those refusals is not a failure at all: a person declining the
    /// lock prompt. [`declined`] writes that one in a form this recognises, so it
    /// arrives as [`Outcome::Declined`] and never as a failure.
    #[must_use]
    pub fn refused(message: String) -> Self {
        if message.contains(DECLINED) {
            Self::Declined { message }
        } else {
            Self::Failed { message, left_behind: Vec::new() }
        }
    }
}

/// How a declined signature is written into a refusal.
const DECLINED: &str = "nothing was signed: signing was declined";

/// A refusal's words for a custody failure, keeping a decline recognisable.
#[must_use]
pub fn declined(cause: &identity::Error) -> String {
    if cause.is_declined() { DECLINED.to_owned() } else { cause.to_string() }
}

/// A command that does not exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unknown {
    /// What was asked for.
    pub name: String,
}

impl fmt::Display for Unknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "there is no `{}` command; there is: ", self.name)?;
        let mut first = true;
        for (word, _) in Command::ALL {
            if !first {
                f.write_str(", ")?;
            }
            f.write_str(word)?;
            first = false;
        }
        Ok(())
    }
}

impl core::error::Error for Unknown {}

/// A device already answering to the name a joining device proposes.
///
/// The identifier is here as well as the name because a name is not an identity.
/// The device asking to join carries different keys and will have a different
/// identifier whatever it is called, so a person choosing to replace is deciding
/// about a name — and is shown the identity that decision falls on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakenName {
    /// The name, as the roster holds it.
    pub name: String,
    /// The short id of the device holding it.
    pub id: String,
}

/// What the daemon sends back over the control channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Outcome {
    /// The command succeeded, with a report.
    Reported(Report),
    /// The command succeeded and there is nothing to say.
    Done,

    /// An enrolment is open and waiting for a person to compare two screens.
    ///
    /// Nothing has been signed. The device this describes is a member of
    /// nothing, and will stay one unless a person confirms.
    Admitting {
        /// The name the joining device proposed for itself.
        proposed_name: String,
        /// Its signing key's fingerprint, in the shape a person can compare.
        fingerprint: String,
        /// The code to display, which the other device's person must type.
        code: String,
        /// The device already answering to the proposed name, if one does.
        ///
        /// `Some` means the admission stops here for an answer:
        /// [`Command::Confirm`] admits under a name no device holds, and
        /// [`Command::Replace`] keeps the name and revokes the device named
        /// below. Before this, the second device quietly became `name-2` and the
        /// admin learned of it from the device list.
        taken: Option<TakenName>,
        /// Whether that device has said the code was accepted.
        ///
        /// False until it does. What this side's person is asked depends on it:
        /// until the far side has confirmed, there is nothing to ask about, and
        /// asking anyway is how a person answers a question about a screen that
        /// has not changed yet.
        accepted: bool,
    },

    /// An admin has reached this device, and a person must type what that
    /// machine is showing.
    ///
    /// It carries **no code**. The device derived one, and telling the person
    /// what it is would turn typing back into agreeing: they would read it from
    /// this screen instead of the admin's, and this screen is the one an
    /// attacker who dialled first controls. A client cannot display what it is
    /// never given.
    Enrolling,
    /// A join is waiting for an admin to come to this device.
    ///
    /// Nothing has been signed and this device is a member of nothing. The
    /// payload is what a person carries to an admin.
    Joining {
        /// The payload as text.
        payload: String,
        /// The same payload, drawn.
        scannable: String,
    },

    /// A join ended with a network adopted.
    Adopted {
        /// The suffix every name in it sits under.
        suffix: String,
        /// How many devices it has, this one included.
        devices: usize,
        /// Whether the relay this device used was confirmed by the network.
        relay_confirmed: bool,
        /// Whether that network is carrying traffic once the join has ended.
        ///
        /// A first join leaves it down: §2.6b makes turning a network on the
        /// person's own act. A join that **replaced** this device's membership
        /// inherits the choice made about that network, so one that was up is up
        /// again — and a surface that ended every join by saying how to turn the
        /// tunnel on would be telling the person to do what has already been done.
        carrying: bool,
    },

    /// A relay certificate is waiting to be confirmed before it is pinned.
    ///
    /// Nothing has been signed. Nothing has vouched for this certificate either:
    /// anyone in the path could have answered, which is why a person is asked to
    /// compare the fingerprint against the relay host before it becomes part of a
    /// signed network.
    Pinning {
        /// The relay it came from.
        relay: String,
        /// Its SHA-256 fingerprint, in the shape `openssl x509` prints.
        fingerprint: String,
        /// How many bytes of DER, so a person can see it is a certificate.
        der_len: usize,
        /// The network being moved to this relay, or `None` for a founding.
        /// A screen resumed from `Waiting` must still say which act it confirms.
        #[serde(default)]
        moving: Option<String>,
    },

    /// The act is prepared and needs signatures this process cannot make.
    ///
    /// **Nothing has been signed and nothing has changed.** The daemon holds what
    /// it prepared and is waiting for [`Command::Signed`] carrying the same id —
    /// or for [`Command::NotSigned`], or for the request to expire.
    NeedsSignatures(SignaturesWanted),

    /// A person declined to sign, and nothing was signed.
    ///
    /// Not a failure. The key that would have signed asks for the phone's lock,
    /// and a person said no or let the prompt time out. The interface says so as
    /// what it is, and nothing about the network changed.
    Declined {
        /// What was not signed, in words.
        message: String,
    },

    /// A signing key must be made where a person can be asked about it.
    ///
    /// **Nothing has been signed and nothing has changed**, and the act is held
    /// exactly as [`Self::NeedsSignatures`] holds one — waiting for
    /// [`Command::KeyMade`] carrying the same id, or expiring.
    ///
    /// It arrives one step earlier than a signature and for the same reason: the
    /// key store asks a person before it will protect a key, the asking needs a
    /// desktop, and a daemon running as the machine has none. Everything that
    /// could refuse this act has refused already, so a person is only shown a
    /// prompt for something that is going to happen.
    NeedsKey(KeyWanted),

    /// The person asking may not ask this.
    ///
    /// **Not a failure, and not the roster refusing.** Nothing about the network
    /// was consulted and nothing about it changed: what was decided is that this
    /// person, on this machine, is not the one it belongs to. Reported as its own
    /// answer so that a surface can say *«that is somebody else's»* rather than
    /// *«something went wrong»*, which sends a person looking for a fault that is
    /// not there.
    NotAllowed {
        /// Why not, naming authority and never membership.
        message: String,
    },

    /// Removing this network would leave it with no admin, and the person has
    /// not said they know that.
    ///
    /// **Nothing was touched.** Its own answer rather than a failure, so that a
    /// surface can put the question — *nobody will be able to admit or revoke
    /// anything in it afterwards, a stolen device included; remove it anyway?* —
    /// and send the removal again with the acknowledgement. Without it, a
    /// network nobody can administer is one that cannot expel a stolen device.
    OnlyAdmin {
        /// The network, by the name it is reported under.
        network: String,
    },

    /// What is open, each port to the one network it was opened to.
    ///
    /// **Never produced on a phone**, which has no firewall rules to write.
    Exposed {
        /// One per rule, as the firewall holds it.
        rules: Vec<crate::exposing::Exposure>,
    },

    /// The command failed.
    ///
    /// Carries the step and what is still on the machine, in words, because the
    /// useful question after a failed bring-up is what the machine looks like.
    Failed {
        /// What happened.
        message: String,
        /// What the daemon installed and has not removed.
        left_behind: Vec<String>,
    },
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod exposure_words {
    use super::*;
    use crate::exposing::Protocol;

    fn words(all: &[&str]) -> Vec<String> {
        all.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn an_exposure_is_read_from_its_words() {
        assert_eq!(
            Command::Expose {
                network: Some("casa".to_owned()),
                protocol: Protocol::Tcp,
                port: 8000
            },
            Command::exposure("expose", &words(&["casa", "tcp", "8000"])).unwrap()
        );
        assert_eq!(
            Command::Unexpose {
                network: Some("casa".to_owned()),
                protocol: Protocol::Udp,
                port: 53
            },
            Command::exposure("unexpose", &words(&["casa", "UDP", "53"])).unwrap()
        );
    }

    #[test]
    fn a_missing_word_a_wrong_protocol_or_a_port_out_of_range_is_refused() {
        for wrong in [
            &["casa", "tcp"][..],
            &["tcp", "8000"][..],
            &["casa", "icmp", "8000"][..],
            &["casa", "tcp", "0"][..],
            &["casa", "tcp", "65536"][..],
            &["casa", "tcp", "http"][..],
            &["--network", "tcp", "80"][..],
            &["casa", "tcp", "80", "extra"][..],
        ] {
            assert!(Command::exposure("expose", &words(wrong)).is_err(), "{wrong:?}");
        }
    }

    /// The owner, as an administrator: a firewall rule is the machine's.
    #[test]
    fn exposing_is_the_owners_as_an_administrator_and_listing_the_owners() {
        let casa = Some("casa".to_owned());
        let expose = Command::Expose { network: casa.clone(), protocol: Protocol::Tcp, port: 1 };
        let unexpose =
            Command::Unexpose { network: casa.clone(), protocol: Protocol::Tcp, port: 1 };
        assert_eq!(Needs::TheOwnerOfAsAdministrator(casa.clone()), expose.needs());
        assert_eq!(Needs::TheOwnerOfAsAdministrator(casa.clone()), unexpose.needs());
        assert!(expose.needs_administrator() && unexpose.needs_administrator());
        assert_eq!(Needs::TheOwnerOf(casa.clone()), Command::Exposed { network: casa }.needs());
        assert_eq!(Needs::Nobody, Command::Exposed { network: None }.needs());
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use core::time::Duration;

    use super::*;

    /// A drawn report as one line, for asserting on what it says rather than on
    /// where it breaks.
    ///
    /// The drawing wraps at a margin and marks every line with the rule of the
    /// block it belongs to, so a sentence can arrive split across two lines. What
    /// these tests are about is the sentence.
    fn said(drawn: &str) -> String {
        let mut out = String::new();
        for line in drawn.lines() {
            let text = line.trim_start_matches(['▌', '│']).trim();
            if !out.is_empty() && !text.is_empty() {
                out.push(' ');
            }
            out.push_str(text);
        }
        out
    }

    fn report(standing: Standing, waiting: Vec<Waiting>) -> Report {
        Report {
            networks: vec![network(standing, waiting)],
            unusable: Vec::new(),
            note: None,
            admin_refusal: None,
            elsewhere: 0,
            may_stop_the_daemon: true,
            could_stop_the_daemon: false,
        }
    }

    fn network(standing: Standing, waiting: Vec<Waiting>) -> Network {
        Network {
            label: "test".to_owned(),
            tunnel: Tunnel::Down,
            standing,
            address: Some(Ipv6Addr::LOCALHOST),
            ipv4: Some(Ipv4State::Held(Ipv4Addr::new(100, 64, 0, 1))),
            name: Some("this.example.internal".to_owned()),
            id: "0b0b-0b0b-0b0b-0b0b".to_owned(),
            admin: true,
            custody: Custody::HeldHere,
            owner_taken: false,
            confirmation: None,
            relay: Some("https://relay.example:443".to_owned()),
            rendezvous: Some("https://meet.example".to_owned()),
            relay_pinned: true,
            relay_leaving: None,
            accused: Vec::new(),
            peers: vec![Peer {
                name: "nas.example.internal".to_owned(),
                name_resolves: true,
                id: "0a0a-0a0a-0a0a-0a0a".to_owned(),
                address: Ipv6Addr::LOCALHOST,
                ipv4: Some(Ipv4State::Held(Ipv4Addr::new(100, 64, 0, 2))),
                reachable: true,
                path: Some(Path::Relay),
                standing,
                last_contact: Contact::NoneRecorded,
            }],
            revoked: Vec::new(),
            waiting,
            waiting_unlisted: 0,
            problem: None,
        }
    }

    /// Each IPv4 state reads as what it is: the address, the device it collides
    /// with, or the conflict that withholds it.
    #[test]
    fn each_ipv4_state_says_what_is_true() {
        let held = Ipv4State::Held(Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(held.to_string(), "100.64.0.2");

        let collides = Ipv4State::Collides(named("tablet", 8));
        let said = collides.to_string();
        assert!(said.contains("collides") && said.contains("tablet"), "{said}");

        let withheld = Ipv4State::Withheld {
            address: Ipv4Addr::new(192, 168, 1, 9),
            with: "the local subnet 192.168.1.0/24".to_owned(),
        };
        let said = withheld.to_string();
        assert!(said.contains("192.168.1.9") && said.contains("withheld"), "{said}");
        assert!(said.contains("192.168.1.0/24"), "and names the conflict: {said}");

        let mut report = report(Standing::Current, Vec::new());
        the_one(&mut report).peers.first_mut().unwrap().ipv4 = Some(withheld);
        let status = report.to_string();
        assert!(
            status.contains("ipv4") && status.contains("100.64.0.1"),
            "this device's own: {status}"
        );
        let peers = report.peers(None).to_string();
        assert!(peers.contains("withheld here"), "a peer's, where peers are: {peers}");
    }

    #[test]
    fn a_peers_path_is_said_beside_its_reachability() {
        let mut report = report(Standing::Current, Vec::new());
        assert!(
            report.peers(None).to_string().contains("yes, via relay"),
            "{}",
            report.peers(None)
        );

        the_one(&mut report).peers.first_mut().unwrap().path = Some(Path::Direct);
        assert!(report.peers(None).to_string().contains("yes, direct"), "{}", report.peers(None));

        the_one(&mut report).peers.first_mut().unwrap().path = None;
        let shown = report.peers(None).to_string();
        assert!(!shown.contains("direct") && !shown.contains("via relay"), "no guess: {shown}");
    }

    #[test]
    fn every_path_round_trips() {
        for path in [Path::Direct, Path::Relay] {
            let text = serde_json::to_string(&path).unwrap();
            assert_eq!(serde_json::from_str::<Path>(&text).unwrap(), path, "{text}");
        }
    }

    #[test]
    fn every_ipv4_state_round_trips() {
        for state in [
            Ipv4State::Held(Ipv4Addr::new(100, 64, 0, 2)),
            Ipv4State::Collides(named("tablet", 8)),
            Ipv4State::Withheld {
                address: Ipv4Addr::new(10, 0, 0, 1),
                with: "the relay".to_owned(),
            },
        ] {
            let text = serde_json::to_string(&state).unwrap();
            assert_eq!(serde_json::from_str::<Ipv4State>(&text).unwrap(), state, "{text}");
        }
    }

    /// A device by name, with an id derived from a tag.
    fn named(name: &str, tag: u8) -> Named {
        Named::new(&DeviceId::from_bytes([tag; 32]), Some(name.to_owned()))
    }

    /// An accusation against a device, with two ordinary branches.
    fn accused(name: &str) -> Accused {
        Accused {
            device: named(name, 7),
            pairs: 1,
            first: Branch { does: Act::Admits(named("tablet", 8)), depth: Some(4) },
            second: Branch { does: Act::Revokes(named("phone", 9)), depth: Some(4) },
        }
    }

    /// The one network in a report built by the helper above.
    fn the_one(report: &mut Report) -> &mut Network {
        report.networks.first_mut().expect("the helper builds one")
    }

    /// An equivocation is reported as itself, not as a fault.
    ///
    /// Only the latest fault is shown, so a detection placed there would vanish
    /// behind a dial failure that repeats every minute — and this is the most
    /// serious thing the roster can say.
    #[test]
    fn an_equivocation_is_reported_beside_a_problem() {
        let mut report = report(Standing::Current, Vec::new());
        the_one(&mut report).accused = vec![accused("laptop")];
        the_one(&mut report).problem = Some(crate::node::Fault {
            subsystem: "transport".to_owned(),
            cause: "the peer could not be reached".to_owned(),
            at: SystemTime::UNIX_EPOCH,
        });

        let shown = report.to_string();
        assert!(shown.contains("EQUIVOCATION"), "it must be said: {shown}");
        assert!(shown.contains("laptop"), "and name the device: {shown}");
    }

    /// A detection says what has and has not happened. Nothing is revoked, and
    /// revoking is a person's act — with the command they would use.
    #[test]
    fn a_detection_says_nothing_was_revoked_and_names_the_command() {
        let mut report = report(Standing::Current, Vec::new());
        the_one(&mut report).accused = vec![accused("laptop")];

        let shown = report.to_string();
        assert!(shown.contains("Nothing has been revoked"), "{shown}");
        assert!(shown.contains("peerfectly revoke"), "and name what a person would type: {shown}");
    }

    /// A device restored from a backup produces exactly this evidence, because it
    /// is exactly this situation: one identity in two places, signing on its own.
    /// Saying so is what stops the first reading being that somebody is certainly
    /// an attacker.
    #[test]
    fn a_detection_says_a_restored_backup_looks_the_same() {
        let mut report = report(Standing::Current, Vec::new());
        the_one(&mut report).accused = vec![accused("laptop")];

        let shown = report.to_string();
        assert!(shown.contains("backup"), "the innocent reading must be offered too: {shown}");
    }

    /// Nothing is said when there is nothing to say.
    #[test]
    fn an_ordinary_report_says_nothing_about_equivocation() {
        let shown = report(Standing::Current, Vec::new()).to_string();
        assert!(!shown.contains("EQUIVOCATION"), "{shown}");
    }

    /// The daemon and the person can be reading two different rosters, so what
    /// the daemon loaded has to be visible rather than inferred from behaviour.
    /// An unpinned relay reads as unreachable peers and nothing else, which is
    /// what made this worth a line of its own.
    #[test]
    fn the_relay_and_whether_it_is_pinned_are_reported() {
        let pinned = report(Standing::Current, Vec::new()).to_string();
        assert!(
            pinned.contains("relay https://relay.example:443 (certificate pinned)"),
            "{pinned}"
        );

        let mut unpinned = report(Standing::Current, Vec::new());
        the_one(&mut unpinned).relay_pinned = false;
        assert!(unpinned.to_string().contains("(no certificate pinned)"), "{unpinned}");

        let mut none = report(Standing::Current, Vec::new());
        the_one(&mut none).relay = None;
        assert!(none.to_string().contains("no relay"), "{none}");
    }

    /// A failure a person can act on has to be a failure they can see.
    #[test]
    fn what_went_wrong_is_shown() {
        let mut reported = report(Standing::Current, Vec::new());
        the_one(&mut reported).problem = Some(crate::node::Fault {
            subsystem: "transport".to_owned(),
            cause: "laptop: the peer could not be reached".to_owned(),
            at: SystemTime::UNIX_EPOCH,
        });

        let shown = reported.to_string();
        let lines = shown.lines().filter(|line| line.contains("problem:")).collect::<Vec<_>>();
        let [line] = lines.as_slice() else { panic!("one line: {shown}") };
        assert!(line.contains("[transport]"), "{shown}");
        assert!(line.contains("could not be reached"), "{shown}");
        assert!(!shown.contains("recently"), "and no history: {shown}");
    }

    /// Nothing wrong, nothing said.
    #[test]
    fn a_healthy_report_says_nothing_about_faults() {
        let shown = report(Standing::Current, Vec::new()).to_string();
        assert!(!shown.contains("problem"), "{shown}");
        assert!(!shown.contains("recently"), "{shown}");
    }

    /// A network never up here has nothing known, and says that rather than a
    /// date in 1970.
    #[test]
    fn a_network_never_up_says_nothing_is_known() {
        let never = report(Standing::LastKnown { at: SystemTime::UNIX_EPOCH }, Vec::new());
        let shown = never.to_string();
        assert!(shown.contains("last known: nothing seen yet"), "{shown}");
        assert!(!shown.contains("1970") && !shown.contains("days ago"), "{shown}");
    }

    /// The distinction the whole module exists for.
    #[test]
    fn a_remembered_answer_says_when_it_was_true() {
        let then =
            SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(1_000)).expect("representable");
        let remembered = report(Standing::LastKnown { at: then }, Vec::new());

        assert!(!remembered.only().expect("one").standing.is_current());
        let shown = remembered.to_string();
        // A date and how long ago, never the seconds: which day depends on the
        // zone the test runs in, so only the shape is asserted.
        assert!(shown.contains("last known at 19"), "{shown}");
        assert!(shown.contains("days ago)"), "{shown}");
        assert!(!shown.contains("at 1000"), "{shown}");
        assert!(!shown.contains("(now)"), "a remembered answer must not read as current");
    }

    #[test]
    fn a_current_answer_says_so() {
        let live = report(Standing::Current, Vec::new());
        assert!(live.only().expect("one").standing.is_current());
        assert!(live.to_string().contains("(now)"));
    }

    /// The reason is signed into the roster and kept for whoever reads it. A
    /// typed flag landing inside it would be a permanent record of a typed flag,
    /// in a log that is append-only and cannot be tidied afterwards.
    ///
    /// Tested here rather than in the command line because that is a binary with
    /// no test module, and this is the half that matters: what reaches the
    /// daemon.
    #[test]
    fn a_revocation_carries_a_reason_and_not_the_options_after_it() {
        let command = Command::Revoke {
            network: Some("casa".to_owned()),
            target: Target::Name("laptop".to_owned()),
            reason: "the machine was lost".to_owned(),
        };

        let Command::Revoke { reason, network, .. } = &command else {
            panic!("built as a revocation");
        };
        assert_eq!(reason, "the machine was lost");
        assert!(!reason.contains("--"), "no option ever belongs in a signed reason");
        assert_eq!(network.as_deref(), Some("casa"), "and the network is its own field");
    }

    /// A revocation signed here, owed to the devices given.
    fn revocation_owed_to(owed: &[(&str, bool)]) -> Waiting {
        Waiting {
            does: Act::Revokes(named("stolen", 3)),
            signed_here: Signed::NotRecorded,
            owed: owed
                .iter()
                .zip(20u8..)
                .map(|((name, connected), tag)| Owed {
                    device: named(name, tag),
                    connected: *connected,
                    last_contact: Contact::NoneRecorded,
                })
                .collect(),
        }
    }

    /// A device that has not confirmed, as the person would need to name it.
    fn lagging(name: &str, connected: bool) -> Waiting {
        revocation_owed_to(&[(name, connected)])
    }

    /// An operation nobody else has seen is a decision the person believes they
    /// have made. It has to be visible without being asked for — and naming the
    /// device is the half of it that can be acted on.
    #[test]
    fn unpropagated_operations_name_the_devices_that_lack_them() {
        let waiting = report(Standing::Current, vec![lagging("laptop", false)]);
        assert!(waiting.only().expect("one").has_unpropagated_work());
        let shown = waiting.to_string();
        assert!(shown.contains("laptop"), "the device is named: {shown}");
        assert!(shown.contains("revocation of stolen"), "with what it is missing: {shown}");
        assert!(shown.contains("waiting"), "{shown}");
    }

    /// Waiting is the right advice for a device that has not appeared, and
    /// precisely the wrong advice for one that is connected and still has not
    /// taken the operation. The report has to tell them apart.
    #[test]
    fn a_device_out_of_contact_is_told_to_be_waited_for() {
        let shown = report(Standing::Current, vec![lagging("laptop", false)]).to_string();
        assert!(shown.contains("not in contact"), "{shown}");
        assert!(shown.contains("Leave the tunnel up"), "{shown}");
    }

    #[test]
    fn a_connected_device_that_has_not_confirmed_is_not_a_wait() {
        let shown = report(Standing::Current, vec![lagging("desktop", true)]).to_string();
        assert!(shown.contains("connected"), "{shown}");
        assert!(
            !shown.contains("Leave the tunnel up"),
            "the device is already here; waiting is not the remedy: {shown}"
        );
        assert!(shown.contains("still admits"), "what it costs is said: {shown}");
    }

    /// Both situations at once, each with its own sentence.
    #[test]
    fn each_situation_gets_the_remedy_that_fits_it() {
        let shown = report(
            Standing::Current,
            vec![revocation_owed_to(&[("laptop", false), ("nas", true)])],
        )
        .to_string();
        assert!(shown.contains("Leave the tunnel up"), "{shown}");
        assert!(shown.contains("still admits"), "{shown}");
    }

    /// A device that is its network's only member has nobody to be outstanding
    /// toward. The report must not invent a warning out of that.
    #[test]
    fn nothing_waiting_is_not_mentioned() {
        assert!(!report(Standing::Current, Vec::new()).to_string().contains("waiting"));
    }

    #[test]
    fn every_command_round_trips_through_its_word() {
        for (word, _) in Command::ALL {
            let command = Command::parse(word, None).expect("a listed word parses");
            assert_eq!(command.word(), *word);
        }
    }

    /// A placeholder that appears to work teaches a person a workflow that is not
    /// the one `enrollment-flow` will give them.
    #[test]
    fn enrolment_commands_do_not_exist() {
        for absent in ["join", "show-qr", "enroll", "invite", "pair"] {
            match Command::parse(absent, None) {
                Err(unknown) => {
                    assert_eq!(unknown.name, absent);
                    assert!(
                        unknown.to_string().contains("there is no"),
                        "an absent command must read as absent, not as a failure"
                    );
                }
                Ok(command) => panic!("`{absent}` must not exist, got {command:?}"),
            }
        }
    }

    #[test]
    fn an_unknown_command_says_what_does_exist() {
        let unknown = Command::parse("frobnicate", None).expect_err("no such command");
        let message = unknown.to_string();
        for (word, _) in Command::ALL {
            assert!(message.contains(word), "the list must name `{word}`: {message}");
        }
    }

    /// If reading status needed Administrator, a person would run everything
    /// elevated — worse than the problem elevation solves.
    #[test]
    fn reading_does_not_need_administrator_and_changing_does() {
        assert!(!Command::Status.needs_administrator());
        assert!(!Command::Peers { network: None }.needs_administrator());
        assert!(!Command::Address { network: None }.needs_administrator());

        assert!(Command::Up { network: None }.needs_administrator());
        assert!(Command::Down { network: None }.needs_administrator());

        // The two the daemon decides against the machine rather than against a
        // network, so the hint and the table agree on them.
        assert!(Command::Stop.needs_administrator());
        assert!(Command::TakeOwnership { network: None }.needs_administrator());
    }

    /// **Taking a network is reachable by typing it.**
    ///
    /// It is how a network survives the account that made it being deleted, and
    /// it was implemented with nothing able to ask for it — found by writing the
    /// verification step and discovering the word did not work. A recovery path
    /// that exists only in the tests is not a recovery path.
    #[test]
    fn taking_a_network_is_a_word_a_person_can_type() {
        assert_eq!(
            Ok(Command::TakeOwnership { network: Some("casa".to_owned()) }),
            Command::parse("takeownership", Some("casa".to_owned()))
        );
        assert!(
            Command::ALL.iter().any(|(word, takes)| *word == "takeownership" && *takes),
            "listed, and it names a network"
        );
    }

    #[test]
    fn a_failure_carries_what_is_left_on_the_machine() {
        let outcome = Outcome::Failed {
            message: "failed while installing the resolution rule".to_owned(),
            left_behind: vec!["a route for fd00::/32".to_owned()],
        };
        match outcome {
            Outcome::Failed { message, left_behind } => {
                assert!(message.contains("installing"));
                assert_eq!(left_behind.len(), 1);
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn the_control_protocol_round_trips() {
        let sent = Outcome::Reported(report(Standing::Current, vec![lagging("laptop", false)]));
        let bytes = serde_json::to_vec(&sent).expect("encodes");
        let back: Outcome = serde_json::from_slice(&bytes).expect("decodes");
        assert_eq!(back, sent);
    }

    /// Every command survives the pipe, the enrolment ones included.
    ///
    /// Those three carry the only command that has a payload, and they are the
    /// only ones a person does not type by name — so nothing else would notice
    /// if they stopped encoding.
    #[test]
    fn every_command_round_trips() {
        let all = [
            Command::Status,
            Command::Up { network: None },
            Command::Down { network: None },
            Command::Peers { network: None },
            Command::Address { network: None },
            Command::Stop,
            Command::Admit { network: None, payload: "peerfectly-join-v1:abcdef".to_owned() },
            Command::Confirm,
            Command::Abandon,
            Command::Forget { label: "casa".to_owned(), last_admin: true },
            // Neither of these is typed by a person: they continue an act the
            // daemon began and could not finish, so nothing else would notice if
            // they stopped encoding.
            Command::Signed {
                id: "18f3a-2".to_owned(),
                signatures: vec![vec![0x30, 0x45, 0x02], vec![0x30, 0x44]],
            },
            Command::NotSigned { id: "18f3a-2".to_owned() },
        ];

        for sent in all {
            let bytes = serde_json::to_vec(&sent).expect("encodes");
            let back: Command = serde_json::from_slice(&bytes).expect("decodes");
            assert_eq!(back, sent, "{sent:?} did not survive the pipe");
        }
    }

    /// **A removal sent without the acknowledgement reads as not given**: an
    /// older command line, or one that never asked, cannot remove a network's
    /// last admin by omission.
    #[test]
    fn a_forget_without_the_acknowledgement_is_not_one() {
        let back: Command =
            serde_json::from_str(r#"{"Forget":{"label":"casa"}}"#).expect("decodes");
        assert_eq!(Command::Forget { label: "casa".to_owned(), last_admin: false }, back);
    }

    /// The answer that asks the question survives the pipe, naming the network.
    #[test]
    fn the_only_admin_answer_round_trips() {
        let sent = Outcome::OnlyAdmin { network: "casa".to_owned() };
        let bytes = serde_json::to_vec(&sent).expect("encodes");
        let back: Outcome = serde_json::from_slice(&bytes).expect("decodes");
        assert_eq!(sent, back);
        assert_eq!("only admin", back.kind());
    }

    /// The admitting side's answer carries three things a person reads off a
    /// screen, and all three have to arrive.
    #[test]
    fn an_admitting_answer_round_trips() {
        let sent = Outcome::Admitting {
            proposed_name: "laptop".to_owned(),
            fingerprint: "AB:CD:EF".to_owned(),
            code: "004217".to_owned(),
            // The device already answering to that name, with the identifier the
            // decision falls on — a name is not an identity.
            taken: Some(TakenName {
                name: "laptop".to_owned(),
                id: "0b0b-0b0b-0b0b-0b0b".to_owned(),
            }),
            accepted: false,
        };

        let bytes = serde_json::to_vec(&sent).expect("encodes");
        let back: Outcome = serde_json::from_slice(&bytes).expect("decodes");
        assert_eq!(back, sent);

        let Outcome::Admitting { code, .. } = back else { panic!("the shape must survive") };
        assert_eq!(code, "004217", "a leading zero is part of the code, not formatting");
    }

    /// The request a person is asked to authorise has to survive the pipe with
    /// its bytes intact: a message that changed on the way would be signed, would
    /// verify against nothing, and the refusal would be about a signature rather
    /// than about the channel.
    #[test]
    fn a_wanted_batch_round_trips() {
        let sent = Outcome::NeedsSignatures(SignaturesWanted {
            id: "18f3a-2".to_owned(),
            key: "peerfectly.home.signing".to_owned(),
            network: "home".to_owned(),
            items: vec![
                ToSign {
                    kind: SigningKind::Operation,
                    message: vec![0x00, 0x7f, 0x80, 0xff],
                    payload: vec![0xa1, 0x02, 0x03],
                },
                ToSign { kind: SigningKind::Snapshot, message: vec![0x01], payload: vec![0xa2] },
            ],
        });

        let bytes = serde_json::to_vec(&sent).expect("encodes");
        let back: Outcome = serde_json::from_slice(&bytes).expect("decodes");
        assert_eq!(back, sent, "byte for byte, including the high ones");

        let Outcome::NeedsSignatures(wanted) = back else { panic!("the shape must survive") };
        assert_eq!(
            vec![0x00, 0x7f, 0x80, 0xff],
            wanted.items.first().expect("one").message,
            "what will be signed"
        );
        assert_eq!(
            vec![0xa1, 0x02, 0x03],
            wanted.items.first().expect("one").payload,
            "and what will be shown"
        );
        assert_eq!(
            SigningKind::Snapshot,
            wanted.items.get(1).expect("two").kind,
            "in the order they take effect"
        );
    }

    /// The fields a struct in this file declares, in order.
    fn fields_of(name: &str) -> Vec<String> {
        let source = include_str!("control.rs");
        let declared = source
            .split(&format!("pub struct {name} {{"))
            .nth(1)
            .and_then(|rest| rest.split("\n}").next())
            .expect("the struct is declared");
        declared
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("pub "))
            .map(str::to_owned)
            .collect()
    }

    /// **A request to sign carries no description of itself.**
    ///
    /// This is structural rather than a rule somebody keeps. What a person is
    /// told they are authorising is read from [`ToSign::payload`] — the bytes
    /// that will be signed — and a component that supplied both the bytes and
    /// their label could label them as anything. The daemon is the component
    /// this design stopped trusting with the key, so it is not given the words
    /// either.
    ///
    /// Adding a `description`, `says`, `title` or `act` field here would undo
    /// that quietly: nothing would fail, and a surface would start showing text
    /// the daemon chose. So the field lists are asserted.
    ///
    /// **`network` is the one word the daemon supplies, and it is not about the
    /// act.** It names *whose* key — so a person holding two networks knows which
    /// passphrase is wanted — and says nothing of what is being signed. A daemon
    /// lying about it can make a person type another network's passphrase, which
    /// unlocks nothing; it cannot make an act look like another act.
    #[test]
    fn a_wanted_batch_describes_itself_only_by_its_bytes() {
        assert_eq!(
            vec!["pub kind: SigningKind,", "pub message: Vec<u8>,", "pub payload: Vec<u8>,"],
            fields_of("ToSign"),
            "an item carries what is to be signed and nothing that says what it means. \
             Whoever supplies the bytes must not also supply the words."
        );
        assert_eq!(
            vec![
                "pub id: String,",
                "pub key: String,",
                "pub network: String,",
                "pub items: Vec<ToSign>,",
            ],
            fields_of("SignaturesWanted"),
            "a batch carries its items, whose key, and which network that key is for — \
             and nothing that describes the act"
        );
    }

    /// The same, from the other side: the outcome carries a request and nothing
    /// beside it.
    #[test]
    fn asking_for_a_signature_carries_only_the_request() {
        let source = include_str!("control.rs");
        let outcome = source
            .split("pub enum Outcome {")
            .nth(1)
            .and_then(|rest| rest.split("\n}").next())
            .expect("the enum is declared");
        assert!(
            outcome.contains("NeedsSignatures(SignaturesWanted),"),
            "one field, unnamed, and no second one for a description"
        );
    }

    /// Whose a network is, in the four combinations that can arise.
    ///
    /// The two that look like they need a default are the two that matter: a
    /// network with no owner, asked for by somebody the platform can name, and
    /// an owned network on a platform that cannot name anybody. Both are
    /// refusals, because either default hands a network to whoever asked.
    #[test]
    fn a_network_belongs_to_somebody_or_to_nobody_and_never_to_whoever_asks() {
        let alice = Caller::Identified {
            name: "S-1-5-21-alice".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };
        let bob = Caller::Identified {
            name: "S-1-5-21-bob".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };

        assert!(alice.is(Some("S-1-5-21-alice")), "hers");
        assert!(!bob.is(Some("S-1-5-21-alice")), "and not his");

        assert!(
            Caller::Unattributed.is(None),
            "where the platform draws no distinction there is nobody to keep out"
        );

        assert!(
            !alice.is(None),
            "a network that says nothing about whose it is does not become hers by her asking"
        );
        assert!(
            !Caller::Unattributed.is(Some("S-1-5-21-alice")),
            "and one that is somebody's is not opened by a caller with no name"
        );
    }

    /// A name is compared whole. Two people whose identifiers share a prefix are
    /// two people.
    #[test]
    fn one_name_is_not_another_because_it_starts_the_same() {
        let alice = Caller::Identified {
            name: "S-1-5-21-100".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };
        assert!(!alice.is(Some("S-1-5-21-1000")), "a longer one is a different person");
        assert!(!alice.is(Some("S-1-5-21-10")), "and so is a shorter one");
    }

    /// The three kinds are told apart on the wire, because a proof of possession
    /// is not an administrative act and must not be presented as one.
    #[test]
    fn every_signing_kind_round_trips() {
        for sent in [SigningKind::Operation, SigningKind::Snapshot, SigningKind::Possession] {
            let bytes = serde_json::to_vec(&sent).expect("encodes");
            let back: SigningKind = serde_json::from_slice(&bytes).expect("decodes");
            assert_eq!(back, sent, "{sent:?} did not survive the pipe");
        }
    }

    /// And `identity`'s kinds map onto them one for one, so a kind added there
    /// cannot quietly arrive here as something else.
    #[test]
    fn identitys_kinds_map_onto_the_wires() {
        use identity::detached::RequestKind;
        assert_eq!(SigningKind::Operation, SigningKind::from(RequestKind::Operation));
        assert_eq!(SigningKind::Snapshot, SigningKind::from(RequestKind::Snapshot));
        assert_eq!(SigningKind::Possession, SigningKind::from(RequestKind::Possession));
    }

    /// And the joining side's answer carries no code at all, which is the whole
    /// of it: a client cannot show a person the number they are supposed to be
    /// reading off the other machine.
    #[test]
    fn the_joining_answer_carries_no_code() {
        let bytes = serde_json::to_vec(&Outcome::Enrolling).expect("encodes");
        let back: Outcome = serde_json::from_slice(&bytes).expect("decodes");
        assert_eq!(back, Outcome::Enrolling);

        let text = String::from_utf8(bytes).expect("json is text");
        assert!(!text.contains("code"), "the joining side's answer names no code: {text}");
    }

    /// The digits a person typed travel to the daemon, and a leading zero is
    /// part of them.
    #[test]
    fn a_typed_code_round_trips() {
        let sent = Command::ConfirmJoin { code: "004217".to_owned() };
        let bytes = serde_json::to_vec(&sent).expect("encodes");
        let back: Command = serde_json::from_slice(&bytes).expect("decodes");
        assert_eq!(back, sent);
    }

    /// The three enrolment commands are not among the words a person types, and
    /// they need no elevation: the daemon is already running as whatever it runs
    /// as, and enrolling changes nothing on the machine.
    #[test]
    fn the_enrolment_commands_are_not_typed_by_name() {
        for command in [
            Command::Admit { network: None, payload: String::new() },
            Command::Confirm,
            Command::Abandon,
        ] {
            assert!(command.is_enrolment());
            assert!(!command.needs_administrator());
            assert!(
                !Command::ALL
                    .iter()
                    .any(|(word, _)| Command::parse(word, None).as_ref() == Ok(&command)),
                "{command:?} must not be reachable by typing a word"
            );
        }
    }

    // ---- membership-report ---------------------------------------------------

    #[test]
    fn a_short_id_is_sixteen_lowercase_digits_in_fours() {
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap().wrapping_mul(0x1b);
        }
        let id = short_id(&DeviceId::from_bytes(bytes));
        assert_eq!(id, "001b-3651-6c87-a2bd");
        assert!(
            id.chars().all(|ch| ch == '-' || ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        );
    }

    /// Only the first eight bytes, so a collision can be built for the test that
    /// proves `revoke` refuses one.
    #[test]
    fn a_short_id_depends_on_the_first_eight_bytes_only() {
        let mut one = [0x11u8; 32];
        let mut other = [0x11u8; 32];
        if let Some(byte) = one.get_mut(9) {
            *byte = 0xaa;
        }
        if let Some(byte) = other.get_mut(9) {
            *byte = 0xbb;
        }
        assert_eq!(short_id(&DeviceId::from_bytes(one)), short_id(&DeviceId::from_bytes(other)));
    }

    #[test]
    fn a_typed_id_must_be_all_of_it() {
        assert_eq!(read_short_id("001B36516C87A2BD").as_deref(), Some("001b-3651-6c87-a2bd"));
        assert_eq!(read_short_id("001b-3651-6c87-a2bd").as_deref(), Some("001b-3651-6c87-a2bd"));
        assert_eq!(read_short_id("001b-3651-6c87-a2b"), None, "fifteen digits is part of one");
        assert_eq!(read_short_id("001b-3651-6c87-a2bdx"), None);
        assert_eq!(read_short_id("laptop"), None);
    }

    /// Every class, and that ordinary names are left alone.
    #[test]
    fn text_from_another_device_is_seen_and_not_obeyed() {
        for (hostile, class) in [
            ("lap\u{1b}[2Jtop", "a terminal escape"),
            ("lap\u{7}top", "a control character"),
            ("\u{202e}pot\u{202c}pal", "a right-to-left override"),
            ("lap\u{2066}top", "an isolate"),
            ("lap\u{200b}top", "a zero-width space"),
            ("lap\u{feff}top", "a byte-order mark"),
            ("lap\u{2028}top", "a line separator"),
        ] {
            let drawn = shown(hostile).to_string();
            assert!(
                drawn.chars().all(|ch| !disguises(ch)),
                "{class} reached the output: {drawn:?}"
            );
            assert!(drawn.contains("\\u{"), "{class} is shown as an escape: {drawn:?}");
        }

        for ordinary in ["laptop", "città", "東京", "müller-pc", "phone 2"] {
            assert_eq!(
                shown(ordinary).to_string(),
                ordinary,
                "an ordinary name is its own drawing"
            );
        }
        assert_eq!(shown("a\\u{202e}b").to_string(), "a\\\\u{202e}b", "an escape cannot be faked");
    }

    /// Every roster-sourced string in the rendering, at once.
    #[test]
    fn nothing_in_a_rendered_report_obeys_what_another_device_wrote() {
        let hostile = "x\u{1b}[31m\u{202e}y";
        let mut report = report(Standing::Current, vec![revocation_owed_to(&[(hostile, false)])]);
        let network = the_one(&mut report);
        network.relay = Some(hostile.to_owned());
        network.rendezvous = Some(hostile.to_owned());
        if let Some(peer) = network.peers.first_mut() {
            peer.name = hostile.to_owned();
        }
        network.accused = vec![Accused {
            device: named(hostile, 1),
            pairs: 2,
            first: Branch {
                does: Act::Renames(named(hostile, 2), hostile.to_owned()),
                depth: None,
            },
            second: Branch { does: Act::Admits(named(hostile, 3)), depth: None },
        }];
        network.revoked = vec![Revoked {
            device: named(hostile, 4),
            revocations: vec![Revocation {
                by: named(hostile, 5),
                reason: hostile.to_owned(),
                signer_clock: Signed::NotRecorded,
            }],
            last_contact: Contact::NoneRecorded,
        }];
        network.problem = Some(crate::node::Fault {
            subsystem: "transport".to_owned(),
            cause: hostile.to_owned(),
            at: SystemTime::UNIX_EPOCH,
        });

        let drawn = report.to_string();
        assert!(!drawn.contains('\u{1b}'), "an escape reached the terminal: {drawn:?}");
        assert!(!drawn.contains('\u{202e}'), "an override reached the terminal: {drawn:?}");
    }

    /// Carried exactly as signed: neutralising is how it is drawn, not what is sent.
    #[test]
    fn what_was_signed_is_what_is_carried() {
        let hostile = "x\u{1b}[31m\u{202e}y";
        let sent = Outcome::Reported(report(Standing::Current, vec![lagging(hostile, false)]));
        let back: Outcome = serde_json::from_slice(&serde_json::to_vec(&sent).unwrap()).unwrap();
        let Outcome::Reported(back) = back else { panic!("the shape must survive") };
        let name = back
            .networks
            .first()
            .and_then(|network| network.waiting.first())
            .and_then(|waiting| waiting.owed.first())
            .and_then(|owed| owed.device.name.clone());
        assert_eq!(name.as_deref(), Some(hostile));
    }

    #[test]
    fn a_revoked_device_is_listed_as_held_here_with_the_signers_clock() {
        let then = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(1_757_000_000)).unwrap();
        let mut report = report(Standing::Current, Vec::new());
        the_one(&mut report).revoked = vec![
            Revoked {
                device: named("laptop", 4),
                revocations: vec![Revocation {
                    by: named("nas", 5),
                    reason: "left on a train".to_owned(),
                    signer_clock: Signed::At { time: then },
                }],
                last_contact: Contact::NoneRecorded,
            },
            Revoked {
                device: Named::new(&DeviceId::from_bytes([6; 32]), None),
                revocations: Vec::new(),
                last_contact: Contact::NoneRecorded,
            },
        ];

        let drawn = report.to_string();
        let said = said(&drawn);
        assert!(said.contains("the revocations this device holds"), "{drawn}");
        // 2025-09-04 15:33 UTC: the 4th or the 5th in any zone, never the seconds.
        assert!(said.contains("the revoking device's clock said 2025-09-0"), "{drawn}");
        assert!(!said.contains("1757000000"), "{drawn}");
        assert!(said.contains("left on a train"), "{drawn}");
        assert!(said.contains("0606-0606-0606-0606] (no name held here)"), "{drawn}");
        assert!(
            !drawn.contains("revoked at"),
            "the time is a claim, not when it happened: {drawn}"
        );
    }

    #[test]
    fn no_recorded_contact_is_not_never() {
        let drawn = report(Standing::Current, vec![lagging("laptop", false)]).to_string();
        assert!(said(&drawn).contains("no contact with this device recorded"), "{drawn}");
        assert!(!drawn.to_lowercase().contains("never"), "{drawn}");

        let at = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(1_757_000_040)).unwrap();
        let mut recorded = report(Standing::Current, Vec::new());
        if let Some(peer) = the_one(&mut recorded).peers.first_mut() {
            peer.last_contact = Contact::Recorded { at };
        }
        // A peer's last contact is a peer's business, so it is `peers` that says
        // it — beside the label, rather than in a sentence of its own.
        let drawn = recorded.peers(None).to_string();
        assert!(drawn.contains("contact") && drawn.contains("2025-09-0"), "{drawn}");
        assert!(drawn.contains("ago)") && !drawn.contains("1757000040"), "{drawn}");
    }

    #[test]
    fn an_equivocation_shows_its_branches_and_no_time() {
        let mut report = report(Standing::Current, Vec::new());
        let mut detail = accused("laptop");
        detail.pairs = 6;
        the_one(&mut report).accused = vec![detail];

        let drawn = report.to_string();
        assert!(drawn.contains("branch a: admission of tablet"), "{drawn}");
        assert!(drawn.contains("branch b: revocation of phone"), "{drawn}");
        assert!(drawn.contains("6 conflicting pairs"), "{drawn}");
        assert!(drawn.contains("Nothing has been revoked"), "{drawn}");
        assert!(drawn.contains("backup"), "{drawn}");
        assert!(drawn.contains("peerfectly revoke"), "{drawn}");
        for offer in ["keep", "choose", "discard", "pick", "signed at", "clock"] {
            assert!(
                !drawn.contains(offer),
                "`{offer}` offers a way to settle it or dates it: {drawn}"
            );
        }
    }

    /// A member that confirmed said it holds an operation. Whether it applies it
    /// cannot be seen from here.
    #[test]
    fn a_confirmation_is_never_described_as_enforcement() {
        let drawn = report(
            Standing::Current,
            vec![revocation_owed_to(&[("laptop", false), ("nas", true)])],
        )
        .to_string();
        for claim in ["applies", "applying", "enforces", "enforcing", "in effect"] {
            assert!(
                !drawn.contains(claim),
                "`{claim}` says more than a confirmation shows: {drawn}"
            );
        }
    }

    #[test]
    fn operations_not_listed_are_counted_and_never_hide_a_revocation() {
        let mut report = report(Standing::Current, vec![lagging("laptop", false)]);
        the_one(&mut report).waiting_unlisted = 5;
        let drawn = report.to_string();
        assert!(drawn.contains("and 5 more operations waiting"), "{drawn}");
        assert!(said(&drawn).contains("No revocation is among them"), "{drawn}");
    }

    #[test]
    fn a_time_the_operation_does_not_carry_is_not_dated() {
        assert_eq!(Signed::from_ts(3), Signed::NotRecorded);
        assert!(matches!(Signed::from_ts(1_757_000_040_000), Signed::At { .. }));
        let drawn = report(Standing::Current, vec![lagging("laptop", false)]).to_string();
        assert!(drawn.contains("no time recorded"), "{drawn}");
        assert!(!drawn.contains("1970"), "{drawn}");
    }

    /// **A rendezvous change is an HTTPS address or `--none`, never both, never
    /// neither**, and it is the network's owner's to ask.
    #[test]
    fn a_rendezvous_change_is_read_from_its_words() {
        let words = |text: &str| text.split_whitespace().map(str::to_owned).collect::<Vec<_>>();

        assert_eq!(
            Ok(Command::ChangeRendezvous {
                network: None,
                rendezvous: Some("https://203.0.113.10:8444".to_owned())
            }),
            Command::rendezvous_change(&words("https://203.0.113.10:8444"))
        );
        assert_eq!(
            Ok(Command::ChangeRendezvous { network: Some("casa".to_owned()), rendezvous: None }),
            Command::rendezvous_change(&words("--none --network casa"))
        );
        for refused in ["", "http://a.example:8444", "https://a.example --none", "a.example", "--x"]
        {
            assert!(Command::rendezvous_change(&words(refused)).is_err(), "`{refused}`");
        }

        let casa = Some("casa".to_owned());
        assert_eq!(
            Needs::TheOwnerOf(casa.clone()),
            Command::ChangeRendezvous { network: casa, rendezvous: None }.needs()
        );
    }

    /// A relay change is a transition that pins, unless it is told otherwise.
    #[test]
    fn a_relay_change_is_read_from_its_words() {
        let words = |line: &str| line.split(' ').map(str::to_owned).collect::<Vec<_>>();

        assert_eq!(
            Ok(Command::ChangeRelay {
                network: None,
                relay: "https://b.example".to_owned(),
                pin: true,
                immediately: false,
            }),
            Command::relay_change(&words("https://b.example")),
            "by default: a transition, and the certificate confirmed and pinned"
        );
        assert_eq!(
            Ok(Command::ChangeRelay {
                network: Some("casa".to_owned()),
                relay: "https://b.example".to_owned(),
                pin: false,
                immediately: true,
            }),
            Command::relay_change(&words("--now https://b.example --network casa --no-relay-cert"))
        );
        for wrong in ["", "--now", "https://a https://b", "https://a --frobnicate"] {
            assert!(Command::relay_change(&words(wrong)).is_err(), "`{wrong}` is not a change");
        }
    }

    #[test]
    fn a_renaming_is_read_by_name_or_by_id() {
        let words = |line: &str| line.split(' ').map(str::to_owned).collect::<Vec<_>>();

        assert_eq!(
            Command::renaming(&words("desktop-rjuubb3 studio --network casa")).unwrap(),
            Command::Rename {
                network: Some("casa".to_owned()),
                target: Target::Name("desktop-rjuubb3".to_owned()),
                name: "studio".to_owned(),
            }
        );
        assert_eq!(
            Command::renaming(&words("--id 0a1b-2c3d-4e5f-6a7b Studio")).unwrap(),
            Command::Rename {
                network: None,
                target: Target::Id("0a1b-2c3d-4e5f-6a7b".to_owned()),
                name: "Studio".to_owned(),
            },
            "the name is passed on as typed, for the daemon to check"
        );

        assert!(Command::renaming(&words("laptop")).is_err(), "no new name");
        assert!(Command::renaming(&words("laptop my laptop")).is_err(), "a name of two words");
        assert!(Command::renaming(&words("--id")).is_err(), "an id flag with nothing after it");
        assert!(Command::renaming(&[]).is_err());
    }

    /// A rename waiting to reach every device is listed after it is in force
    /// here, when the device already goes by the new name: by id then, not
    /// "renaming of studio to studio".
    #[test]
    fn a_rename_in_force_names_its_device_once() {
        let pending = Act::Renames(named("laptop", 1), "studio".to_owned());
        assert!(pending.to_string().starts_with("renaming of laptop ["), "{pending}");
        let in_force = Act::Renames(named("studio", 1), "studio".to_owned());
        assert!(in_force.to_string().starts_with("renaming of ["), "{in_force}");
        assert!(in_force.to_string().ends_with("to studio"), "{in_force}");
    }

    /// Renaming acts on a roster, so it is the network owner's, and it signs, so
    /// it is asked from an elevated console as revoking is.
    #[test]
    fn renaming_needs_what_revoking_needs() {
        let rename = Command::Rename {
            network: Some("casa".to_owned()),
            target: Target::Name("laptop".to_owned()),
            name: "studio".to_owned(),
        };
        let revoke = Command::Revoke {
            network: Some("casa".to_owned()),
            target: Target::Name("laptop".to_owned()),
            reason: "lost".to_owned(),
        };
        assert_eq!(rename.needs(), revoke.needs());
        assert_eq!(rename.needs_administrator(), revoke.needs_administrator());
    }

    #[test]
    fn a_revocation_is_read_by_name_or_by_id_and_never_guessed() {
        let words = |line: &str| line.split(' ').map(str::to_owned).collect::<Vec<_>>();

        let by_name = Command::revocation(&words("laptop left on a train --network casa")).unwrap();
        assert_eq!(
            by_name,
            Command::Revoke {
                network: Some("casa".to_owned()),
                target: Target::Name("laptop".to_owned()),
                reason: "left on a train".to_owned(),
            }
        );

        let by_id = Command::revocation(&words("--id 0a1b-2c3d-4e5f-6a7b lost")).unwrap();
        assert_eq!(
            by_id,
            Command::Revoke {
                network: None,
                target: Target::Id("0a1b-2c3d-4e5f-6a7b".to_owned()),
                reason: "lost".to_owned(),
            }
        );

        // A device may be named like an id. Without the flag it is a name.
        let named_like_an_id = Command::revocation(&words("0a1b-2c3d-4e5f-6a7b lost")).unwrap();
        assert!(matches!(named_like_an_id, Command::Revoke { target: Target::Name(_), .. }));

        assert!(Command::revocation(&words("--id")).is_err(), "an id flag with nothing after it");
        assert!(Command::revocation(&words("laptop")).is_err(), "no reason");
        assert!(Command::revocation(&[]).is_err());
    }
}

#[cfg(test)]
mod tray_tests {
    use super::*;

    /// The icon changes on up and on down, and not otherwise.
    #[test]
    fn the_icon_is_redrawn_exactly_when_the_state_changes() {
        assert_eq!(redraw(Tunnel::Down, Tunnel::Up), Some(Tunnel::Up), "coming up redraws");
        assert_eq!(redraw(Tunnel::Up, Tunnel::Down), Some(Tunnel::Down), "going down redraws");

        assert_eq!(redraw(Tunnel::Up, Tunnel::Up), None, "no change, no redraw");
        assert_eq!(redraw(Tunnel::Down, Tunnel::Down), None);
    }

    /// A full cycle leaves the icon showing the truth at every point.
    #[test]
    fn the_icon_follows_a_whole_cycle() {
        let mut shown = Tunnel::Down;

        for state in [Tunnel::Up, Tunnel::Up, Tunnel::Down, Tunnel::Up] {
            if let Some(next) = redraw(shown, state) {
                shown = next;
            }
            assert_eq!(shown, state, "the icon must never lag behind the tunnel");
        }
    }
}

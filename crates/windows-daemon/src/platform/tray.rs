//! The tray icon.
//!
//! Each of the person's networks, with its state, turned on and off from its own
//! submenu; quitting, which turns off this person's networks and closes the tray;
//! starting the service when it is stopped; and, to an administrator, stopping
//! it. Nothing else.
//!
//! # It offers no administrative action
//!
//! No approving a device, no revoking one, nothing that puts a key to work. Those
//! are consequential acts that change who is in a person's network, and a menu
//! next to the clock — hit by accident, with no confirmation and no context — is
//! the wrong place for them.
//!
//! # It is not the only way to control the daemon
//!
//! Everything here has a command-line equivalent, which [`by_hand`] names. A
//! daemon reachable only through a tray is a daemon nobody can run over a remote
//! session, which is exactly how a person administers the machine that most
//! needs this software.
//!
//! # It runs as the person, not as the daemon
//!
//! A mode of `peerfectly.exe`, in the person's own session, speaking the same protocol
//! as every other command. It holds no state: what it shows comes from the
//! report, and what it does is a `Command` on the channel.
//!
//! # It offers only what that person may ask for
//!
//! What it offers comes from [`Offers`], read off the daemon's own answer rather
//! than guessed at from this process's token — guessing would be a second
//! decision beside the one that counts, and the two would eventually disagree.
//! The networks are the report's, so another person's are never in the menu, and
//! quitting sends `down` for what the report listed and nothing else.

use tray_icon::menu::{
    CheckMenuItem, IconMenuItem, IsMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu,
};
use tray_icon::{TrayIcon, TrayIconBuilder};

use daemon::control::{Command, Report, Tunnel};
use daemon::error::{Error, Result, Step};
use daemon::limits;

/// How one network stands, as its icon shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Up, and nothing wrong.
    On,
    /// Down.
    Off,
    /// Something wrong now: a current problem, or a roster this device will not
    /// carry traffic for.
    Problem,
}

/// One network, as the menu shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// What this device calls it.
    pub label: String,
    /// How it stands.
    pub state: State,
    /// Whether its tunnel is up, which is what the check item says.
    pub on: bool,
    /// The network's other devices, as many as are listed.
    pub devices: Vec<Device>,
    /// How many more there are than were listed.
    pub more: usize,
}

/// How many of a network's devices the menu lists before it says how many more.
pub const DEVICES_LISTED: usize = 12;

/// One of a network's other devices, as its line shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Its name, as text another device chose: neutralised before it is drawn.
    pub name: String,
    /// How it is reached.
    pub reach: Reach,
}

/// How a device is reached, as the report says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Directly.
    Direct,
    /// Through the relay.
    Relayed,
    /// Reachable, by a path the report does not name.
    Reachable,
    /// Not reachable now.
    Unreachable,
    /// Not known: the network is off.
    Unknown,
}

impl Device {
    /// Its line in the menu: `laptop — direct`, or just the name when nothing
    /// is known.
    #[must_use]
    pub fn text(&self) -> String {
        let how = match self.reach {
            Reach::Direct => "direct",
            Reach::Relayed => "via relay",
            Reach::Reachable => "reachable",
            Reach::Unreachable => "not reachable",
            Reach::Unknown => return self.name.clone(),
        };
        format!("{} — {how}", self.name)
    }
}

/// The overall state, as the tray icon shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overall {
    /// The daemon did not answer.
    Stopped,
    /// Nothing of this person's is on.
    AllOff,
    /// Something is on, and nothing wrong.
    SomethingOn,
    /// Something is wrong.
    SomethingWrong,
}

/// What a tray may put in its menu.
///
/// A value rather than a set of arguments, so that deciding it is one function
/// somebody can test and not a condition repeated at each `append`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offers {
    /// Whether the daemon answered at all.
    pub answered: bool,
    /// This person's networks, as the report listed them.
    pub networks: Vec<Row>,
    /// Whether to offer stopping the service.
    pub stopping: bool,
    /// Why the daemon is stopped, when there is something to say beyond that.
    pub why: Option<String>,
}

impl Offers {
    /// What the daemon's answer says this person may be offered.
    ///
    /// **Read, not guessed.** The daemon identified whoever asked and decided
    /// what they may do; this is that decision.
    #[must_use]
    pub fn from(report: &Report) -> Self {
        let networks = report
            .networks
            .iter()
            .map(|network| {
                let on = network.tunnel == Tunnel::Up;
                let state = if network.problem.is_some() || network.confirmation.is_some() {
                    State::Problem
                } else if on {
                    State::On
                } else {
                    State::Off
                };
                let devices: Vec<Device> = network
                    .peers
                    .iter()
                    .map(|peer| Device {
                        name: daemon::control::shown(&peer.name).to_string(),
                        reach: if !on {
                            Reach::Unknown
                        } else if !peer.reachable {
                            Reach::Unreachable
                        } else {
                            match peer.path {
                                Some(daemon::control::Path::Direct) => Reach::Direct,
                                Some(daemon::control::Path::Relay) => Reach::Relayed,
                                None => Reach::Reachable,
                            }
                        },
                    })
                    .collect();
                let more = devices.len().saturating_sub(DEVICES_LISTED);
                let devices = devices.into_iter().take(DEVICES_LISTED).collect();
                Row { label: network.label.clone(), state, on, devices, more }
            })
            .collect();
        // Offered to whoever may stop it now, and to whoever could after
        // Windows' prompt: the tray is never elevated, and the stop it offers is
        // asked again by a process that is, which is what the daemon decides.
        let stopping = report.may_stop_the_daemon || report.could_stop_the_daemon;
        Self { answered: true, networks, stopping, why: None }
    }

    /// A daemon that did not answer, and why, when that is known.
    #[must_use]
    pub const fn stopped(why: Option<String>) -> Self {
        Self { answered: false, networks: Vec::new(), stopping: false, why }
    }

    /// The overall state.
    #[must_use]
    pub fn overall(&self) -> Overall {
        if !self.answered {
            Overall::Stopped
        } else if self.networks.iter().any(|row| row.state == State::Problem) {
            Overall::SomethingWrong
        } else if self.networks.iter().any(|row| row.on) {
            Overall::SomethingOn
        } else {
            Overall::AllOff
        }
    }

    /// The first line of the menu, and the tooltip.
    #[must_use]
    pub fn header(&self) -> String {
        if !self.answered {
            return format!("{} is stopped", limits::PRODUCT);
        }
        let total = self.networks.len();
        if total == 0 {
            return format!("{} — no networks of yours", limits::PRODUCT);
        }
        let on = self.networks.iter().filter(|row| row.on).count();
        let wrong = self.networks.iter().filter(|row| row.state == State::Problem).count();
        let mut said = format!("{} — {on} of {total} on", limits::PRODUCT);
        if wrong > 0 {
            said.push_str(&format!(" · {wrong} with a problem"));
        }
        said
    }

    /// What decides whether the menu is rebuilt rather than updated: which
    /// networks, and which devices in each. A device's state changing is only
    /// an update, so an open menu is not replaced under the pointer.
    #[allow(clippy::type_complexity, reason = "compared, never read")]
    fn shape(&self) -> (bool, bool, Vec<(&str, Vec<&str>, usize)>) {
        let networks = self
            .networks
            .iter()
            .map(|row| {
                let names = row.devices.iter().map(|device| device.name.as_str()).collect();
                (row.label.as_str(), names, row.more)
            })
            .collect();
        (self.answered, self.stopping, networks)
    }
}

/// What the person asked for through the tray.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Wish {
    /// Turn this network on.
    On(String),
    /// Turn this network off.
    Off(String),
    /// Turn off this person's networks and close the tray.
    Quit,
    /// Stop the service, for everybody.
    StopService,
    /// Start the stopped service.
    StartService,
    /// Start the tray at login, or not.
    StartAtLogin(bool),
}

/// What a wish comes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sends {
    /// These commands, on the channel, as this person.
    Commands(Vec<Command>),
    /// `peerfectly stop`, run elevated, so that the daemon's own check decides.
    ElevatedStop,
    /// Asking the control manager to start the service.
    StartTheService,
    /// Writing or removing this person's login entry.
    AtLogin(bool),
}

/// What a wish sends, given what was offered.
///
/// **Quit sends ordinary `down`s**, one per network of this person's that is on,
/// so it is recorded as their choice with no new command and no new rule, and
/// another person's networks are untouched by construction: the report never
/// listed them. A network the report did not list is sent nothing.
#[must_use]
pub fn sends(wish: &Wish, offers: &Offers) -> Sends {
    let listed = |label: &str| offers.networks.iter().any(|row| row.label == label);
    match wish {
        Wish::On(label) if listed(label) => {
            Sends::Commands(vec![Command::Up { network: Some(label.clone()) }])
        }
        Wish::Off(label) if listed(label) => {
            Sends::Commands(vec![Command::Down { network: Some(label.clone()) }])
        }
        Wish::On(_) | Wish::Off(_) => Sends::Commands(Vec::new()),
        Wish::Quit => Sends::Commands(
            offers
                .networks
                .iter()
                .filter(|row| row.on)
                .map(|row| Command::Down { network: Some(row.label.clone()) })
                .collect(),
        ),
        Wish::StopService => Sends::ElevatedStop,
        Wish::StartService => Sends::StartTheService,
        Wish::StartAtLogin(on) => Sends::AtLogin(*on),
    }
}

/// The same act, from a console: what a person types where there is no tray.
#[must_use]
pub fn by_hand(wish: &Wish) -> String {
    match wish {
        Wish::On(label) => format!("peerfectly up {label}"),
        Wish::Off(label) => format!("peerfectly down {label}"),
        Wish::Quit => "peerfectly down <each network of yours>".to_owned(),
        Wish::StopService => "peerfectly stop (as an administrator)".to_owned(),
        Wish::StartService => "sc start peerfectly".to_owned(),
        Wish::StartAtLogin(_) => "Settings › Apps › Startup".to_owned(),
    }
}

/// One entry of the menu, before anything is drawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// The overall state, not clickable.
    Header(String),
    /// A separator.
    Separator,
    /// A network's submenu.
    Network(Row),
    /// Whether the tray starts at login.
    StartAtLogin(bool),
    /// Stopping the service.
    StopService,
    /// Starting it.
    StartService,
    /// Quitting.
    Quit,
}

/// The menu for what is offered.
///
/// **Absent, not greyed out.** An item a person can see and click and be refused
/// teaches them the menu is decoration; one that is not there says what it is:
/// not theirs.
#[must_use]
pub fn layout(offers: &Offers, at_login: bool) -> Vec<Entry> {
    let mut entries = vec![Entry::Header(offers.header()), Entry::Separator];
    if offers.answered {
        if !offers.networks.is_empty() {
            entries.extend(offers.networks.iter().cloned().map(Entry::Network));
            entries.push(Entry::Separator);
        }
    } else {
        entries.push(Entry::StartService);
    }
    entries.push(Entry::StartAtLogin(at_login));
    if offers.stopping {
        entries.push(Entry::StopService);
    }
    entries.push(Entry::Separator);
    entries.push(Entry::Quit);
    entries
}

/// A square picture, `size` pixels a side, as RGBA.
type Picture = Vec<u8>;

/// The colour a state is shown in.
const fn colour(state: State) -> [u8; 4] {
    match state {
        State::On => [0x2e, 0xb8, 0x5c, 0xff],
        State::Off => [0x8a, 0x8f, 0x98, 0xff],
        State::Problem => [0xe8, 0x9a, 0x1c, 0xff],
    }
}

/// A disc of `colour` centred at (`cx`, `cy`), drawn onto `picture`.
fn disc(picture: &mut Picture, size: u32, (cx, cy, radius): (f32, f32, f32), colour: [u8; 4]) {
    for y in 0..size {
        for x in 0..size {
            #[expect(clippy::cast_precision_loss, reason = "a picture is at most 32 pixels")]
            let (dx, dy) = (x as f32 + 0.5 - cx, y as f32 + 0.5 - cy);
            if dx.mul_add(dx, dy * dy) <= radius * radius {
                let at = y
                    .checked_mul(size)
                    .and_then(|row| row.checked_add(x))
                    .and_then(|pixel| pixel.checked_mul(4))
                    .and_then(|at| usize::try_from(at).ok())
                    .unwrap_or(usize::MAX);
                if let Some(pixel) = picture.get_mut(at..at.saturating_add(4)) {
                    pixel.copy_from_slice(&colour);
                }
            }
        }
    }
}

/// The tray icon for an overall state, 32 pixels square: a light ring, the
/// product's mark, with a dot in the state's colour.
#[must_use]
pub fn picture(overall: Overall) -> Picture {
    const SIZE: u32 = 32;
    let mut picture = vec![0; (SIZE * SIZE * 4) as usize];
    disc(&mut picture, SIZE, (14.0, 14.0, 12.0), [0xe6, 0xe8, 0xec, 0xff]);
    disc(&mut picture, SIZE, (14.0, 14.0, 7.5), [0, 0, 0, 0]);
    let dot = match overall {
        Overall::Stopped => [0x4a, 0x4e, 0x55, 0xff],
        Overall::AllOff => colour(State::Off),
        Overall::SomethingOn => colour(State::On),
        Overall::SomethingWrong => colour(State::Problem),
    };
    disc(&mut picture, SIZE, (24.0, 24.0, 7.5), dot);
    picture
}

/// A network's dot, 16 pixels square.
#[must_use]
pub fn dot(state: State) -> Picture {
    const SIZE: u32 = 16;
    let mut picture = vec![0; (SIZE * SIZE * 4) as usize];
    disc(&mut picture, SIZE, (8.0, 8.0, 5.0), colour(state));
    picture
}

/// A device's dot, 16 pixels square: green when reached directly, a lighter
/// green through the relay, grey otherwise.
#[must_use]
pub fn device_dot(reach: Reach) -> Picture {
    const SIZE: u32 = 16;
    let colour = match reach {
        Reach::Direct | Reach::Reachable => colour(State::On),
        Reach::Relayed => [0x8f, 0xd8, 0xa8, 0xff],
        Reach::Unreachable | Reach::Unknown => colour(State::Off),
    };
    let mut picture = vec![0; (SIZE * SIZE * 4) as usize];
    disc(&mut picture, SIZE, (8.0, 8.0, 4.0), colour);
    picture
}

/// One network's items in the menu.
struct Drawn {
    /// Its submenu, carrying the state's dot.
    submenu: Submenu,
    /// Whether it is on.
    check: CheckMenuItem,
    /// Its devices, one item each, not clickable.
    devices: Vec<IconMenuItem>,
}

/// The tray icon and its menu.
pub struct Tray {
    /// The icon. Dropping it removes it from the tray.
    icon: TrayIcon,
    /// The overall state, the first line.
    header: MenuItem,
    /// Each network's items, in the order offered.
    networks: Vec<(String, Drawn)>,
    /// Whether the tray starts at login.
    at_login: CheckMenuItem,
    /// What the menu was built for, so a change of shape rebuilds it.
    built_for: Offers,
}

/// The id of each item that does something.
const QUIT: &str = "quit";
const STOP: &str = "stop-service";
const START: &str = "start-service";
const LOGIN: &str = "start-at-login";
const NETWORK: &str = "network:";

impl Tray {
    /// Puts the icon in the tray.
    ///
    /// Must be called on the thread that pumps messages — see [`super::pump`].
    ///
    /// # Errors
    ///
    /// When the icon cannot be created, which on a session with no desktop is the
    /// ordinary outcome rather than a fault.
    pub fn show(offers: &Offers, at_login: bool) -> Result<Self> {
        let (menu, header, networks, login) = Self::menu(offers, at_login)?;
        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip(Self::tooltip(offers))
            .with_icon(Self::icon_for(offers.overall())?)
            .build()
            .map_err(|cause| Self::failed(&cause))?;
        Ok(Self { icon, header, networks, at_login: login, built_for: offers.clone() })
    }

    /// Shows what the daemon now says.
    ///
    /// **Rebuilt when the set of networks changes, updated in place when only
    /// their states do**, so an open menu is not replaced under the person's
    /// pointer every two seconds.
    pub fn showing(&mut self, offers: &Offers) {
        if offers == &self.built_for {
            return;
        }
        if offers.shape() != self.built_for.shape() {
            let at_login = self.at_login.is_checked();
            if let Ok((menu, header, networks, login)) = Self::menu(offers, at_login) {
                self.icon.set_menu(Some(Box::new(menu)));
                self.header = header;
                self.networks = networks;
                self.at_login = login;
            }
        } else {
            self.header.set_text(offers.header());
            for (row, (_, drawn)) in offers.networks.iter().zip(&self.networks) {
                drawn.check.set_checked(row.on);
                drawn.submenu.set_icon(Self::menu_icon(row.state));
                for (device, item) in row.devices.iter().zip(&drawn.devices) {
                    item.set_text(device.text());
                    item.set_icon(Self::device_icon(device.reach));
                }
            }
        }
        let _ = self.icon.set_tooltip(Some(Self::tooltip(offers)));
        if offers.overall() != self.built_for.overall()
            && let Ok(icon) = Self::icon_for(offers.overall())
        {
            let _ = self.icon.set_icon(Some(icon));
        }
        self.built_for = offers.clone();
    }

    /// Whether the start-at-login item is checked.
    pub fn starts_at_login(&self, on: bool) {
        self.at_login.set_checked(on);
    }

    /// What the person clicked, if anything.
    ///
    /// Non-blocking, so the thread that owns the icon can pump messages and check
    /// this in the same loop.
    #[must_use]
    pub fn wish(&self) -> Option<Wish> {
        let event = MenuEvent::receiver().try_recv().ok()?;
        let id = event.id.0.as_str();
        match id {
            QUIT => Some(Wish::Quit),
            STOP => Some(Wish::StopService),
            START => Some(Wish::StartService),
            // The item has already toggled itself; what it says now is the wish.
            LOGIN => Some(Wish::StartAtLogin(self.at_login.is_checked())),
            _ => {
                let label = id.strip_prefix(NETWORK)?;
                let (_, drawn) = self.networks.iter().find(|(held, _)| held == label)?;
                Some(if drawn.check.is_checked() {
                    Wish::On(label.to_owned())
                } else {
                    Wish::Off(label.to_owned())
                })
            }
        }
    }

    /// Builds the menu of [`layout`].
    #[expect(clippy::type_complexity, reason = "the parts `showing` keeps, returned together")]
    fn menu(
        offers: &Offers,
        at_login: bool,
    ) -> Result<(Menu, MenuItem, Vec<(String, Drawn)>, CheckMenuItem)> {
        let menu = Menu::new();
        let mut header = MenuItem::new("", false, None);
        let mut networks = Vec::new();
        let mut login = CheckMenuItem::with_id(LOGIN, "Start at login", true, at_login, None);

        for entry in layout(offers, at_login) {
            let item: Box<dyn IsMenuItem> = match entry {
                Entry::Header(text) => {
                    header = MenuItem::new(text, false, None);
                    Box::new(header.clone())
                }
                Entry::Separator => Box::new(PredefinedMenuItem::separator()),
                Entry::Network(row) => {
                    let submenu = Submenu::new(&row.label, true);
                    submenu.set_icon(Self::menu_icon(row.state));
                    let check = CheckMenuItem::with_id(
                        format!("{NETWORK}{}", row.label),
                        "On",
                        true,
                        row.on,
                        None,
                    );
                    submenu.append(&check).map_err(|cause| Self::failed(&cause))?;
                    let devices: Vec<IconMenuItem> = row
                        .devices
                        .iter()
                        .map(|device| {
                            IconMenuItem::new(
                                device.text(),
                                false,
                                Self::device_icon(device.reach),
                                None,
                            )
                        })
                        .collect();
                    if !devices.is_empty() {
                        submenu
                            .append(&PredefinedMenuItem::separator())
                            .map_err(|cause| Self::failed(&cause))?;
                    }
                    for device in &devices {
                        submenu.append(device).map_err(|cause| Self::failed(&cause))?;
                    }
                    if row.more > 0 {
                        let more = MenuItem::new(
                            format!("and {} more — peerfectly peers {}", row.more, row.label),
                            false,
                            None,
                        );
                        submenu.append(&more).map_err(|cause| Self::failed(&cause))?;
                    }
                    networks.push((
                        row.label.clone(),
                        Drawn { submenu: submenu.clone(), check, devices },
                    ));
                    Box::new(submenu)
                }
                Entry::StartAtLogin(on) => {
                    login = CheckMenuItem::with_id(LOGIN, "Start at login", true, on, None);
                    Box::new(login.clone())
                }
                Entry::StopService => {
                    Box::new(MenuItem::with_id(STOP, "Stop service…", true, None))
                }
                Entry::StartService => Box::new(MenuItem::with_id(
                    START,
                    format!("Start {}", limits::PRODUCT),
                    true,
                    None,
                )),
                Entry::Quit => Box::new(MenuItem::with_id(
                    QUIT,
                    format!("Quit {}", limits::PRODUCT),
                    true,
                    None,
                )),
            };
            menu.append(item.as_ref()).map_err(|cause| Self::failed(&cause))?;
        }
        Ok((menu, header, networks, login))
    }

    /// The tooltip: the header, and why the daemon is stopped when that is known.
    fn tooltip(offers: &Offers) -> String {
        match &offers.why {
            Some(why) => format!("{} — {why}", offers.header()),
            None => offers.header(),
        }
    }

    /// The tray icon for an overall state.
    fn icon_for(overall: Overall) -> Result<tray_icon::Icon> {
        tray_icon::Icon::from_rgba(picture(overall), 32, 32).map_err(|cause| Self::failed(&cause))
    }

    /// A network's dot, for its submenu.
    fn menu_icon(state: State) -> Option<tray_icon::menu::Icon> {
        tray_icon::menu::Icon::from_rgba(dot(state), 16, 16).ok()
    }

    /// A device's dot, for its item.
    fn device_icon(reach: Reach) -> Option<tray_icon::menu::Icon> {
        tray_icon::menu::Icon::from_rgba(device_dot(reach), 16, 16).ok()
    }

    /// Wraps a tray failure.
    fn failed(cause: &dyn core::fmt::Display) -> Error {
        Error::BringUp {
            step: Step::StartingResolver,
            cause: format!("the tray icon could not be shown: {cause}"),
            left: Vec::new(),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "a test reports failure by panicking"
)]
mod tests {
    use daemon::control::{Command, Report, Tunnel};

    use super::{Entry, Offers, Overall, State, Wish, by_hand, dot, layout, picture, sends};

    /// A report holding `networks` of this person's, as (label, up, problem).
    fn told(networks: &[(&str, bool, bool)], may_stop: bool) -> Report {
        let mut report: Report =
            serde_json::from_str(include_str!("../../../daemon/tests/fixtures/control.json"))
                .map(|outcomes: serde_json::Value| {
                    serde_json::from_value(outcomes["outcomes"][0]["Reported"].clone()).unwrap()
                })
                .unwrap();
        let template = report.networks.first().cloned().unwrap();
        report.networks = networks
            .iter()
            .map(|(label, up, problem)| {
                let mut network = template.clone();
                network.label = (*label).to_owned();
                network.tunnel = if *up { Tunnel::Up } else { Tunnel::Down };
                network.confirmation = None;
                if !problem {
                    network.problem = None;
                }
                network
            })
            .collect();
        report.may_stop_the_daemon = may_stop;
        report.could_stop_the_daemon = false;
        report
    }

    /// **A person who owns nothing is offered only Quit and starting at login.**
    #[test]
    fn a_person_with_no_network_is_offered_only_quit_and_login() {
        let offers = Offers::from(&told(&[], false));
        let entries = layout(&offers, true);

        let acts: Vec<&Entry> = entries
            .iter()
            .filter(|entry| !matches!(entry, Entry::Header(_) | Entry::Separator))
            .collect();
        assert_eq!(acts, vec![&Entry::StartAtLogin(true), &Entry::Quit], "{entries:?}");
    }

    /// A network with a current problem is shown as one.
    #[test]
    fn a_network_with_a_problem_is_shown_as_one() {
        let offers = Offers::from(&told(&[("casa", true, true), ("lavoro", false, false)], false));

        assert_eq!(State::Problem, offers.networks[0].state);
        assert_eq!(State::Off, offers.networks[1].state);
        assert_eq!(Overall::SomethingWrong, offers.overall());
        assert!(offers.header().contains("1 with a problem"), "{}", offers.header());
    }

    /// *Stop service* appears only when the report says so.
    #[test]
    fn stopping_is_offered_only_when_the_report_says_so() {
        for may in [false, true] {
            let offers = Offers::from(&told(&[("casa", true, false)], may));
            assert_eq!(may, layout(&offers, false).contains(&Entry::StopService));
        }
    }

    /// **An administrator at an unelevated console is offered stopping**: the
    /// tray is never elevated, and the prompt comes when it is chosen.
    #[test]
    fn one_prompt_away_is_offered_stopping() {
        let mut report = told(&[("casa", true, false)], false);
        report.could_stop_the_daemon = true;
        assert!(layout(&Offers::from(&report), false).contains(&Entry::StopService));
    }

    /// A stopped daemon offers starting it, and no network.
    #[test]
    fn a_stopped_daemon_offers_starting_it() {
        let offers = Offers::stopped(None);
        let entries = layout(&offers, false);

        assert!(entries.contains(&Entry::StartService));
        assert!(!entries.iter().any(|entry| matches!(entry, Entry::Network(_))));
        assert_eq!(Overall::Stopped, offers.overall());
        assert!(offers.header().contains("stopped"), "{}", offers.header());
    }

    /// One, two and no networks: a submenu each, in order.
    #[test]
    fn each_network_has_its_own_submenu() {
        for labels in [vec![], vec!["casa"], vec!["casa", "lavoro"]] {
            let networks: Vec<(&str, bool, bool)> =
                labels.iter().map(|label| (*label, false, false)).collect();
            let offers = Offers::from(&told(&networks, false));
            let drawn: Vec<String> = layout(&offers, false)
                .into_iter()
                .filter_map(|entry| match entry {
                    Entry::Network(row) => Some(row.label),
                    _ => None,
                })
                .collect();
            assert_eq!(labels, drawn);
        }
    }

    /// **Quit sends one `down` per network of this person's that is on, and
    /// nothing for one that is off.**
    #[test]
    fn quit_turns_off_only_what_is_on() {
        let offers = Offers::from(&told(&[("casa", true, false), ("lavoro", false, false)], false));
        assert_eq!(
            super::Sends::Commands(vec![Command::Down { network: Some("casa".to_owned()) }]),
            sends(&Wish::Quit, &offers)
        );
    }

    /// **A network the report did not list is sent nothing.** Another person's
    /// networks are never in the report, so never in reach.
    #[test]
    fn a_network_not_listed_is_sent_nothing() {
        let offers = Offers::from(&told(&[("casa", false, false)], false));
        for wish in [Wish::On("theirs".to_owned()), Wish::Off("theirs".to_owned())] {
            assert_eq!(super::Sends::Commands(Vec::new()), sends(&wish, &offers));
        }
        assert_eq!(
            super::Sends::Commands(vec![Command::Up { network: Some("casa".to_owned()) }]),
            sends(&Wish::On("casa".to_owned()), &offers)
        );
    }

    /// Everything the tray offers is also a command, so the daemon is usable
    /// over a session with no desktop.
    #[test]
    fn every_tray_action_is_also_a_command() {
        for wish in [
            Wish::On("casa".to_owned()),
            Wish::Off("casa".to_owned()),
            Wish::Quit,
            Wish::StopService,
            Wish::StartService,
            Wish::StartAtLogin(false),
        ] {
            let typed = by_hand(&wish);
            assert!(!typed.is_empty(), "{wish:?}");
        }
        assert_eq!("peerfectly up casa", by_hand(&Wish::On("casa".to_owned())));
        assert!(by_hand(&Wish::StopService).starts_with("peerfectly stop"));
    }

    /// `casa`, up, with these devices as (name, reachable, path).
    fn with_devices(devices: &[(&str, bool, Option<daemon::control::Path>)], up: bool) -> Offers {
        let mut report = told(&[("casa", up, false)], false);
        let network = report.networks.first_mut().unwrap();
        let template = network.peers.first().cloned().unwrap();
        network.peers = devices
            .iter()
            .map(|(name, reachable, path)| {
                let mut peer = template.clone();
                peer.name = (*name).to_owned();
                peer.reachable = *reachable;
                peer.path = *path;
                peer
            })
            .collect();
        Offers::from(&report)
    }

    /// **Each device reads as how it is reached**, and this device's own
    /// addresses are not in the menu.
    #[test]
    fn each_device_reads_as_how_it_is_reached() {
        use daemon::control::Path;

        let offers = with_devices(
            &[
                ("laptop", true, Some(Path::Direct)),
                ("phone", true, Some(Path::Relay)),
                ("nas", false, None),
            ],
            true,
        );
        let said: Vec<String> =
            offers.networks[0].devices.iter().map(super::Device::text).collect();
        assert_eq!(said, ["laptop — direct", "phone — via relay", "nas — not reachable"]);
    }

    /// With the network off, the devices are named and nothing is said of them.
    #[test]
    fn a_network_off_lists_names_with_no_state() {
        let offers = with_devices(&[("laptop", true, Some(daemon::control::Path::Direct))], false);
        assert_eq!("laptop", offers.networks[0].devices[0].text());
        assert_eq!(super::Reach::Unknown, offers.networks[0].devices[0].reach);
    }

    /// **Past twelve, a line says how many more**, and where to see them.
    #[test]
    fn thirteen_devices_list_twelve_and_a_line() {
        let names: Vec<String> = (0..13).map(|n| format!("device-{n}")).collect();
        let devices: Vec<(&str, bool, Option<daemon::control::Path>)> =
            names.iter().map(|name| (name.as_str(), false, None)).collect();
        let offers = with_devices(&devices, true);

        assert_eq!(super::DEVICES_LISTED, offers.networks[0].devices.len());
        assert_eq!(1, offers.networks[0].more);
    }

    /// **A device's name is another device's text**: a control character in it
    /// is neutralised before it reaches the menu.
    #[test]
    fn a_devices_name_is_neutralised() {
        let offers = with_devices(&[("evil\u{202e}gnp.exe", false, None)], true);
        let drawn = offers.networks[0].devices[0].text();
        assert!(!drawn.contains('\u{202e}'), "{drawn:?}");
    }

    /// **A device admitted rebuilds the menu; a device's state changing only
    /// updates it**, so an open menu is not replaced under the pointer.
    #[test]
    fn only_the_set_of_devices_changes_the_shape() {
        use daemon::control::Path;

        let before = with_devices(&[("laptop", true, Some(Path::Direct))], true);
        let moved = with_devices(&[("laptop", true, Some(Path::Relay))], true);
        let admitted =
            with_devices(&[("laptop", true, Some(Path::Direct)), ("phone", false, None)], true);

        assert_eq!(before.shape(), moved.shape(), "a state changing is an update");
        assert_ne!(before.shape(), admitted.shape(), "a device admitted is a rebuild");
    }

    /// Each state draws a well-formed picture, and the states differ.
    #[test]
    fn each_state_draws_its_own_picture() {
        let drawn: Vec<Vec<u8>> =
            [Overall::Stopped, Overall::AllOff, Overall::SomethingOn, Overall::SomethingWrong]
                .into_iter()
                .map(picture)
                .collect();
        for one in &drawn {
            assert_eq!(32 * 32 * 4, one.len());
        }
        for (at, one) in drawn.iter().enumerate() {
            for other in drawn.iter().skip(at + 1) {
                assert_ne!(one, other, "two states look the same");
            }
        }
        assert_ne!(dot(State::On), dot(State::Problem));
        assert_eq!(16 * 16 * 4, dot(State::Off).len());
    }

    /// **What is offered is read off the daemon's answer, not worked out here.**
    #[test]
    fn what_is_offered_is_the_daemons_decision() {
        let code = crate::code_of(include_str!("tray.rs"));
        let deciding = code
            .split("pub fn from(")
            .nth(1)
            .and_then(|rest| rest.split("pub const fn stopped").next())
            .expect("it is declared");

        for guessing in ["token", "elevated", "Administrator", "current_exe", "std::env"] {
            assert!(!deciding.contains(guessing), "`{guessing}` would be a second decision");
        }
        assert!(deciding.contains("report.may_stop_the_daemon"), "it reads the answer: {deciding}");
    }

    /// A menu next to the clock is the wrong place for a consequential act.
    #[test]
    fn the_tray_offers_no_administrative_action() {
        let code = crate::code_of(include_str!("tray.rs"));

        for forbidden in ["approve", "revoke", "sign", "admit", "AddDevice", "Role"] {
            assert!(
                !code.contains(forbidden),
                "`{forbidden}` in a tray menu is a consequential act one click away"
            );
        }
    }

    /// The tray reports what the person wants; it does not act. Acting on a
    /// message-loop thread would be a second path into the daemon's state.
    #[test]
    fn the_tray_does_not_act_on_its_own() {
        let code = crate::code_of(include_str!("tray.rs"));
        for forbidden in ["Lifecycle", "Node", "Machine", "exit("] {
            assert!(!code.contains(forbidden), "`{forbidden}` would let the tray act directly");
        }
    }
}

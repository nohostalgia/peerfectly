//! The three answers a report can give, and which one each command asks for.
//!
//! One report, three questions. *What does this device hold and is it working*
//! is `status`; *who else is in this network and can I reach them* is `peers`;
//! *what is my address* is `address`. They used to be one answer to all three,
//! which meant the first was read by scrolling past the second: on a device
//! holding three networks, finding out whether one was up meant reading every
//! peer, revocation and fault of all of them.
//!
//! Nothing here asks the daemon for anything. Every view is a reading of the
//! same [`Report`] the daemon already answers with, which is what keeps the
//! phone — which reads that report's fields and draws its own surface — out of
//! this entirely.
//!
//! # Where each thing goes
//!
//! Anything that demands attention stays in `status`: an equivocation, work that
//! has not propagated, a current problem. They are the reason a person runs the
//! command at all, and a device's address is not.
//!
//! Every value another device wrote passes through [`shown`] before it is drawn,
//! exactly as it did before. The drawing never aligns anything after a value, so
//! what a device calls itself cannot move anything else on the page — see
//! [`crate::drawing`].

use core::fmt;

use crate::control::{Contact, Network, Peer, Report, Signed, shown};
use crate::drawing::Block;

impl Report {
    /// The devices in each network: what `peers` answers.
    ///
    /// Named a network, it describes that one; named none, it describes every
    /// network this device holds. A name that this device does not hold is
    /// refused before it reaches here — by the daemon, which is what knows.
    #[must_use]
    pub const fn peers<'a>(&'a self, network: Option<&'a str>) -> Peers<'a> {
        Peers { report: self, network }
    }

    /// This device's own address: what `address` answers.
    #[must_use]
    pub const fn address<'a>(&'a self, network: Option<&'a str>) -> Address<'a> {
        Address { report: self, network }
    }

    /// The networks this report covers, narrowed to one when a name is given.
    fn covered<'a>(&'a self, network: Option<&'a str>) -> impl Iterator<Item = &'a Network> {
        self.networks.iter().filter(move |held| match network {
            Some(name) => held.label == name,
            None => true,
        })
    }
}

/// The devices in each network, as `peers` draws them.
#[derive(Debug, Clone, Copy)]
pub struct Peers<'a> {
    /// The report being read.
    report: &'a Report,
    /// The network asked about, if one was named.
    network: Option<&'a str>,
}

/// This device's own address, as `address` draws it.
#[derive(Debug, Clone, Copy)]
pub struct Address<'a> {
    /// The report being read.
    report: &'a Report,
    /// The network asked about, if one was named.
    network: Option<&'a str>,
}

/// The state of every network, which is what a report says when nothing says
/// otherwise.
///
/// `status` prints this, and so does every command that ends by showing what the
/// device now holds — founding, joining, admitting. They all ask the same
/// question at that moment: *what is true now*.
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(note) = &self.note {
            writeln!(f, "{note}")?;
        }

        // Nothing below this is true of a device with no network. Printing
        // "relay: none — direct paths only" would describe a network that does
        // not exist, which is worse than saying less.
        for (position, network) in self.networks.iter().enumerate() {
            if position > 0 {
                writeln!(f)?;
            }
            write!(f, "{}", status_of(network))?;
        }

        for unusable in &self.unusable {
            writeln!(f)?;
            let mut block = Block::headed(format!("{}   could not be carried", unusable.label));
            // The cause is a value, not text another device wrote, so it is
            // drawn as this surface says it rather than passed through `shown`.
            block.note(unusable.cause.to_string());
            block.plain(
                "Every other network is unaffected. Nothing here has been changed or replaced.",
            );
            write!(f, "{block}")?;
        }

        // **Said whenever there are any, not only when there are none of yours.**
        // A person with one network of their own and two of somebody else's has
        // the same question as one with none: why there is a network name on
        // this machine they cannot use. The `note` only covers the empty case,
        // and the empty case is not the confusing one.
        if self.elsewhere > 0 {
            writeln!(f)?;
            let mut block = Block::headed("not yours".to_owned());
            block.note(match self.elsewhere {
                1 => "one network on this machine belongs to somebody else".to_owned(),
                many => format!("{many} networks on this machine belong to other people"),
            });
            block.plain(
                "Nothing about them is shown here, and nothing you ask can reach them. Whoever they belong to can use them, and an administrator can take one over.",
            );
            write!(f, "{block}")?;
        }

        // A fact about the machine rather than about any one network, and the
        // answer to why founding was refused — so it is said even on a device
        // that holds nothing, where there is no network block to hang it on.
        if let Some(why) = &self.admin_refusal {
            writeln!(f)?;
            let mut block = Block::headed("this machine cannot be an admin".to_owned());
            block.note(why.clone());
            block.plain(
                "It can join a network and be a member of it. Founding one here is refused.",
            );
            write!(f, "{block}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Peers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for network in self.report.covered(self.network) {
            if !first {
                writeln!(f)?;
            }
            first = false;

            writeln!(f, "{}   {}", network.label, counted(network))?;
            if network.peers.is_empty() {
                writeln!(f)?;
                writeln!(f, "  no other device is in it yet")?;
                continue;
            }
            for peer in &network.peers {
                writeln!(f)?;
                write!(f, "{}", entry_for(peer))?;
            }
        }
        if first {
            writeln!(f, "this device holds no network")?;
        }
        Ok(())
    }
}

impl fmt::Display for Address<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut any = false;
        for network in self.report.covered(self.network) {
            any = true;
            match (network.address, &network.ipv4) {
                (Some(address), Some(ipv4)) => {
                    writeln!(f, "{}   {address}   {ipv4}", network.label)?;
                }
                (Some(address), None) => writeln!(f, "{}   {address}", network.label)?,
                (None, _) => {
                    writeln!(f, "{}   not yet known", network.label)?;
                }
            }
        }
        if !any {
            writeln!(f, "this device holds no network")?;
        }
        Ok(())
    }
}

/// One network's state, as `status` draws it.
fn status_of(network: &Network) -> Block {
    let mut block =
        Block::headed(format!("{}   {} ({})", network.label, network.tunnel, network.standing));

    // This device's name is in the roster, and so is text another device can
    // have written: an admin renames it.
    let role = if network.admin { "admin" } else { "member" };
    match &network.name {
        Some(name) => {
            block.line("this device", format!("{} [{}], {role}", shown(name), network.id))
        }
        None => block.line("this device", format!("[{}], not in the roster held here", network.id)),
    }

    match network.address {
        Some(address) => block.line("address", address),
        None => block.line("address", "not yet known"),
    }
    if let Some(ipv4) = &network.ipv4 {
        block.line("ipv4", ipv4);
    }
    block.line("devices", counted(network));
    block.line("infrastructure", infrastructure(network));
    // Where **this** device keeps the key that signs for this network. Never
    // said about a peer: this device cannot see how somebody else holds theirs.
    block.line("signing key", network.custody);

    warnings(network, &mut block);
    block
}

/// One device, as `peers` draws it.
fn entry_for(peer: &Peer) -> Block {
    let mut block = Block::headed(format!("{} [{}]", shown(&peer.name), peer.id));

    match &peer.ipv4 {
        Some(ipv4) => block.line("addresses", format!("{}   {ipv4}", peer.address)),
        None => block.line("addresses", peer.address),
    }

    let reached = match (peer.reachable, peer.path) {
        (true, Some(path)) => format!("yes, {path}"),
        (true, None) => "yes".to_owned(),
        (false, _) => "no".to_owned(),
    };
    // Whether that answer is live or remembered is the difference between a
    // device that is there and one that was.
    block.line("reachable", format!("{reached} ({})", peer.standing));
    block.line("contact", contact_of(&peer.last_contact));
    block
}

/// How many devices a network holds, and how many it has expelled.
///
/// Derived rather than carried: the report lists the *other* devices, so this
/// device is counted when the roster names it, and is not when it does not —
/// which is the state a device is in between joining and being admitted.
fn counted(network: &Network) -> String {
    let others = network.peers.len();
    let devices = others.saturating_add(usize::from(network.name.is_some()));
    let word = if devices == 1 { "device" } else { "devices" };
    if network.revoked.is_empty() {
        format!("{devices} {word}")
    } else {
        format!("{devices} {word}, {} revoked", network.revoked.len())
    }
}

/// Where a network's infrastructure is, in one line.
///
/// Always drawn, whether or not anything is wrong with it. The daemon and the
/// person reading this can be using two different profiles — one elevated, one
/// not — and nothing else in the report would show it. That cost a day of
/// two-machine testing once.
fn infrastructure(network: &Network) -> String {
    let relay = match (&network.relay, network.relay_pinned) {
        (Some(relay), true) => format!("relay {} (certificate pinned)", shown(relay)),
        (Some(relay), false) => format!("relay {} (no certificate pinned)", shown(relay)),
        (None, _) => "no relay — direct paths only".to_owned(),
    };
    let line = match &network.rendezvous {
        Some(meeting) => format!("{relay}, meet {}", shown(meeting)),
        None => format!("{relay}, no rendezvous"),
    };
    // **Said, because whoever runs the old relay needs to read it.** Switched
    // off before the end, it strands every device that has not come back yet —
    // and nothing else on this screen would tell them it is still in use.
    match &network.relay_leaving {
        Some(leaving) => format!(
            "{line}; moving from {} — everybody stays there until {}, so keep it running until then",
            shown(&leaving.relay),
            crate::drawing::when(leaving.until)
        ),
        None => line,
    }
}

/// When a device last spoke, without the sentence the report carries.
fn contact_of(contact: &Contact) -> String {
    match contact {
        Contact::Recorded { at } => format!("at {}", crate::drawing::when(*at)),
        Contact::NoneRecorded => "none recorded".to_owned(),
    }
}

/// Everything about a network that asks to be noticed.
///
/// Equivocations first, because nothing the roster can say is more serious, then
/// what has not propagated, then what is wrong now. All of it stays
/// in `status`: it is why a person runs the command.
fn warnings(network: &Network, block: &mut Block) {
    // Before the rest. A network this device will not carry traffic for is not a
    // detail among the faults: every reachability line below it is about to read
    // as unreachable, and this is the only thing that says why. A person seeing
    // their devices stop answering with no explanation would conclude the
    // product is broken, which is the nearest reading available to them.
    if let Some(why) = network.confirmation {
        block.blank();
        block.note(format!("THIS ROSTER IS {}.", why.to_string().to_uppercase()));
        block.note(why.remedy().to_owned());
    }

    for accused in &network.accused {
        block.blank();
        block.note(format!("EQUIVOCATION: {} signed two conflicting histories.", accused.device));
        for (letter, branch) in [("a", &accused.first), ("b", &accused.second)] {
            match branch.depth {
                Some(depth) => {
                    block.plain(format!("  branch {letter}: {} (depth {depth})", branch.does))
                }
                None => block.plain(format!("  branch {letter}: {}", branch.does)),
            }
        }
        if accused.pairs > 1 {
            block.plain(format!(
                "  {} conflicting pairs from this device are held; one is shown.",
                accused.pairs
            ));
        }
        block.plain("Nothing has been revoked. Expelling a device is a signed act, and yours:");
        block.plain(format!("  peerfectly revoke <name> <reason> --network {}", network.label));
        block.plain(format!("  peerfectly revoke --id <id> <reason> --network {}", network.label));
        block.plain(
            "A device restored from a backup looks exactly like this, because it is the same \
             thing: one identity in two places, signing on its own. Find out which before \
             deciding.",
        );
    }

    if network.has_unpropagated_work() {
        block.blank();
        block.note("waiting: signed operations have not reached every device");
        for waiting in &network.waiting {
            match waiting.signed_here {
                Signed::At { time } => block.plain(format!(
                    "  {} — signed here at {}",
                    waiting.does,
                    crate::drawing::when(time)
                )),
                _ => block.plain(format!("  {} — signed here, no time recorded", waiting.does)),
            }
            for owed in &waiting.owed {
                if owed.connected {
                    block.plain(format!(
                        "    {} — connected, and has not said it holds it",
                        owed.device
                    ));
                } else {
                    block.plain(format!(
                        "    {} — not in contact; {}",
                        owed.device, owed.last_contact
                    ));
                }
            }
        }
        if network.waiting_unlisted > 0 {
            block.plain(format!(
                "  and {} more operations waiting, not listed here. No revocation is among them.",
                network.waiting_unlisted
            ));
        }

        // The remedy, chosen from what is actually true. A number with no remedy
        // trains a person to ignore the number; a remedy that does not apply to
        // their situation trains them faster.
        //
        // Two conditions and not two branches of one: a network can hold both a
        // device that has not appeared and one that is here and has not taken
        // the operation, and each of those has an answer of its own.
        let owed = || network.waiting.iter().flat_map(|waiting| waiting.owed.iter());
        if owed().any(|device| !device.connected) {
            block.plain(
                "Leave the tunnel up. A device is sent these the moment it is in contact, by \
                 this device or by any other member that already holds them.",
            );
        }
        if owed().any(|device| device.connected) {
            block.plain(
                "A device that stays connected without saying it holds them has not taken \
                 them. Until it does, it still admits anything these operations revoke.",
            );
        }
    }

    if !network.revoked.is_empty() {
        block.blank();
        block.plain("revoked — the revocations this device holds:");
        for revoked in &network.revoked {
            block.plain(format!("  {} — {}", revoked.device, revoked.last_contact));
            for revocation in &revoked.revocations {
                let clock = match revocation.signer_clock {
                    Signed::At { time } => {
                        format!("the revoking device's clock said {}", crate::drawing::when(time))
                    }
                    _ => "the revoking device recorded no time".to_owned(),
                };
                block.plain(format!(
                    "    by {}: \"{}\" ({clock})",
                    revocation.by,
                    shown(&revocation.reason)
                ));
            }
        }
    }

    // One line, the latest and only while recent. The history is the service's
    // log; a list here kept showing failures long since over.
    if let Some(problem) = &network.problem {
        block.blank();
        // A fault can quote a device's name, and a name is another device's text.
        block.note(format!("problem: [{}] {}", problem.subsystem, shown(&problem.cause)));
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "a test reports failure by panicking, and builds its own fixtures"
)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::control::{Ipv4State, Path, Peer, Standing, Tunnel};

    /// A drawn view as one line, for asserting on what it says rather than on
    /// where the margin put a break.
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

    fn peer(name: &str, id: &str, reachable: bool) -> Peer {
        Peer {
            name: name.to_owned(),
            id: id.to_owned(),
            address: Ipv6Addr::LOCALHOST,
            ipv4: Some(Ipv4State::Held(Ipv4Addr::new(100, 64, 0, 2))),
            reachable,
            path: reachable.then_some(Path::Relay),
            standing: Standing::Current,
            last_contact: Contact::NoneRecorded,
        }
    }

    fn network(label: &str, peers: Vec<Peer>) -> Network {
        Network {
            label: label.to_owned(),
            tunnel: Tunnel::Up,
            standing: Standing::Current,
            address: Some(Ipv6Addr::LOCALHOST),
            ipv4: Some(Ipv4State::Held(Ipv4Addr::new(100, 64, 0, 1))),
            name: Some("this.example.internal".to_owned()),
            id: "0b0b-0b0b-0b0b-0b0b".to_owned(),
            admin: true,
            custody: crate::control::Custody::HeldHere,
            owner_taken: false,
            confirmation: None,
            relay: Some("https://relay.example:443".to_owned()),
            rendezvous: None,
            relay_pinned: true,
            relay_leaving: None,
            accused: Vec::new(),
            peers,
            revoked: Vec::new(),
            waiting: Vec::new(),
            waiting_unlisted: 0,
            problem: None,
        }
    }

    /// **A network mid-move says which relay is still needed, and until when.**
    /// And nothing about it once the move is over.
    #[test]
    fn a_move_in_progress_is_shown_and_then_is_not() {
        let mut moving = network("casa", Vec::new());
        moving.relay = Some("https://new.example:443".to_owned());
        moving.relay_leaving = Some(crate::control::RelayLeaving {
            relay: "https://old.example:443".to_owned(),
            until: std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(1_758_300_000),
        });
        let drawn = infrastructure(&moving);
        assert!(drawn.contains("old.example"), "which relay: {drawn}");
        assert!(drawn.contains("keep it running"), "and what to do about it: {drawn}");

        moving.relay_leaving = None;
        assert!(!infrastructure(&moving).contains("old.example"), "nothing, after the end");
    }

    fn two_networks() -> Report {
        Report {
            networks: vec![
                network("casa", vec![peer("nas.casa.internal", "0a0a-0a0a-0a0a-0a0a", true)]),
                network(
                    "lavoro",
                    vec![peer("laptop.lavoro.internal", "0c0c-0c0c-0c0c-0c0c", false)],
                ),
            ],
            unusable: Vec::new(),
            note: None,
            admin_refusal: None,
            elsewhere: 0,
            may_stop_the_daemon: true,
            could_stop_the_daemon: false,
        }
    }

    /// Status is about networks. Everything a person runs it for is here — and a
    /// device's detail, which they did not run it for, is not.
    #[test]
    fn status_says_what_this_device_holds_and_not_who_else_is_in_it() {
        let drawn = two_networks().to_string();

        for expected in [
            "casa",
            "lavoro",
            "up",
            "this device",
            "this.example.internal",
            "0b0b-0b0b-0b0b-0b0b",
            "::1",
            "100.64.0.1",
            "2 devices",
            "relay https://relay.example:443 (certificate pinned)",
        ] {
            assert!(said(&drawn).contains(expected), "status says `{expected}`: {drawn}");
        }

        assert!(!drawn.contains("nas.casa.internal"), "a peer's name is `peers` business: {drawn}");
        assert!(!drawn.contains("reachable"), "and so is whether it answers: {drawn}");
    }

    /// Where the infrastructure is, said whether or not anything is wrong with
    /// it: a daemon and a command line can be reading two different profiles,
    /// and nothing else in the report would show it.
    #[test]
    fn status_says_where_the_infrastructure_is_even_when_it_is_in_order() {
        let drawn = two_networks().to_string();
        assert!(drawn.contains("infrastructure"), "{drawn}");
        assert!(said(&drawn).contains("no rendezvous"), "an absent one is still said: {drawn}");

        let mut without = two_networks();
        without.networks[0].relay = None;
        assert!(said(&without.to_string()).contains("no relay"), "{without}");
    }

    /// Peers is about devices, one entry each.
    #[test]
    fn peers_says_who_else_is_in_a_network() {
        let report = two_networks();
        let drawn = report.peers(Some("casa")).to_string();

        assert!(drawn.contains("nas.casa.internal"), "{drawn}");
        assert!(drawn.contains("0a0a-0a0a-0a0a-0a0a"), "{drawn}");
        assert!(drawn.contains("yes, via relay"), "{drawn}");
        assert!(drawn.contains("contact"), "{drawn}");
        assert!(!drawn.contains("laptop.lavoro.internal"), "one network was named: {drawn}");
    }

    /// Named none, it describes every network this device holds — grouped, so
    /// which devices belong to which is never a guess.
    #[test]
    fn peers_with_no_network_named_describes_them_all() {
        let report = two_networks();
        let drawn = report.peers(None).to_string();

        assert!(drawn.contains("nas.casa.internal"), "{drawn}");
        assert!(drawn.contains("laptop.lavoro.internal"), "{drawn}");
        assert!(drawn.contains("casa") && drawn.contains("lavoro"), "grouped by network: {drawn}");
    }

    /// A device that is not answering says so, and says nothing about a path it
    /// does not have.
    #[test]
    fn a_peer_that_is_not_reachable_is_not_given_a_path() {
        let report = two_networks();
        let drawn = report.peers(Some("lavoro")).to_string();
        assert!(drawn.contains("no ("), "{drawn}");
        assert!(!drawn.contains("via relay") && !drawn.contains("direct"), "no guess: {drawn}");
    }

    /// A network with nobody else in it is a state, not an empty list.
    #[test]
    fn peers_says_when_a_network_holds_nobody_else() {
        let mut report = two_networks();
        report.networks[0].peers.clear();
        let drawn = report.peers(Some("casa")).to_string();
        assert!(drawn.contains("no other device"), "{drawn}");
    }

    /// An address is an address.
    #[test]
    fn address_answers_with_an_address_and_nothing_else() {
        let report = two_networks();
        let drawn = report.address(Some("casa")).to_string();

        assert!(drawn.contains("::1") && drawn.contains("100.64.0.1"), "{drawn}");
        assert!(!drawn.contains("relay"), "not the infrastructure: {drawn}");
        assert!(!drawn.contains("nas.casa.internal"), "not the peers: {drawn}");
        assert_eq!(drawn.lines().count(), 1, "one network named, one line: {drawn}");
        assert_eq!(report.address(None).to_string().lines().count(), 2, "one line each");
    }

    /// The whole point: three commands, three answers.
    #[test]
    fn the_three_views_are_three_different_answers() {
        let report = two_networks();
        let status = report.to_string();
        let peers = report.peers(None).to_string();
        let address = report.address(None).to_string();

        assert_ne!(status, peers);
        assert_ne!(status, address);
        assert_ne!(peers, address);
        assert!(address.len() < peers.len(), "an address is the shortest answer");
        assert!(address.len() < status.len());
    }

    /// **No time is printed as a count of seconds.** Every time a view draws
    /// goes through `drawing::when`; reading seconds off a `SystemTime` here, or
    /// in a `Display` of the report, is how the raw form would come back.
    #[test]
    fn no_time_is_drawn_as_seconds() {
        let views = crate::code_of(include_str!("views.rs"));
        let control = crate::code_of(include_str!("control.rs"));
        let displays: Vec<&str> = control
            .split("impl fmt::Display for ")
            .skip(1)
            .map(|rest| rest.split("\n}\n").next().unwrap_or(rest))
            .collect();
        assert!(displays.len() > 5, "the report's `Display` impls were not found");

        for (place, code) in std::iter::once(("views.rs", views.as_str()))
            .chain(displays.iter().map(|code| ("a Display in control.rs", *code)))
        {
            for raw in ["as_secs()", "UNIX_EPOCH"] {
                assert!(!code.contains(raw), "`{raw}` in {place}: a time drawn as seconds");
            }
        }
    }

    /// **`status` no longer names the tray.** It starts at login now, and a
    /// block about it on every `status` was noise once it did.
    #[test]
    fn the_report_does_not_name_the_tray() {
        let drawn = Report {
            networks: Vec::new(),
            unusable: Vec::new(),
            note: None,
            admin_refusal: None,
            elsewhere: 0,
            may_stop_the_daemon: true,
            could_stop_the_daemon: false,
        }
        .to_string();

        assert!(!drawn.contains("tray"), "{drawn}");
    }

    /// A device holding nothing is a state with a remedy, not an empty report.
    #[test]
    fn a_device_with_no_network_is_told_so_by_every_view() {
        let empty = Report {
            networks: Vec::new(),
            unusable: Vec::new(),
            note: None,
            admin_refusal: None,
            elsewhere: 0,
            may_stop_the_daemon: true,
            could_stop_the_daemon: false,
        };
        assert!(empty.peers(None).to_string().contains("holds no network"));
        assert!(empty.address(None).to_string().contains("holds no network"));
    }

    /// A network this device will not carry traffic for says so, before anything
    /// else that could be read as the reason. Every reachability line under it is
    /// about to read as unreachable, and this is the only thing that explains it.
    #[test]
    fn a_roster_that_cannot_be_confirmed_is_said_and_says_the_remedy() {
        for (why, word) in [
            (crate::control::Unconfirmed::Stale, "NOT CONFIRMED"),
            (crate::control::Unconfirmed::NeverAttested, "NEVER CONFIRMED"),
            (crate::control::Unconfirmed::ClockMoved, "CLOCK MOVED"),
        ] {
            let mut one = network("casa", Vec::new());
            one.confirmation = Some(why);
            let drawn = Report {
                networks: vec![one],
                unusable: Vec::new(),
                note: None,
                admin_refusal: None,
                elsewhere: 0,
                may_stop_the_daemon: true,
                could_stop_the_daemon: false,
            }
            .to_string();

            assert!(drawn.contains(word), "it names which of the three it is: {drawn}");
            assert!(drawn.contains("administrator"), "and what a person does about it: {drawn}");
        }
    }

    /// And a network that is simply quiet says none of it. The two must not look
    /// alike: one has something to do about it, the other does not.
    #[test]
    fn a_confirmed_roster_says_nothing_about_confirmation() {
        let drawn = Report {
            networks: vec![network("casa", Vec::new())],
            unusable: Vec::new(),
            note: None,
            admin_refusal: None,
            elsewhere: 0,
            may_stop_the_daemon: true,
            could_stop_the_daemon: false,
        }
        .to_string();

        assert!(!drawn.contains("administrator"), "nothing is being waited for: {drawn}");
        assert!(!drawn.to_uppercase().contains("CONFIRMED"), "{drawn}");
    }
}

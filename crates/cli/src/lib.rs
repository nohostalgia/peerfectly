//! The command line, on any platform.
//!
//! Asks the running daemon and prints what it says. It holds no state of its own
//! and takes no decisions: everything here is a question or an instruction sent
//! over the control channel, so there is no second place where the truth about
//! the tunnel lives.
//!
//! # What a platform gives it
//!
//! Two things, and nothing else about the machine:
//!
//! - a [`Channel`]: a request out, an answer back — a named pipe on Windows, a
//!   socket on Linux;
//! - [`Custody`]: making a signing key and signing with it, in the session of
//!   the person at the machine — or [`NoCustody`], where the machine cannot
//!   protect a key, and every act that needs one is refused in words.
//!
//! **What is about to be signed is read here, off the bytes, and checked against
//! the act that was asked for**, on every platform, by this one copy. Two copies
//! would be two chances to show a person different things before a signature.
//!
//! Reading state needs no privilege. Changing it does, and the daemon — not this
//! — is what runs privileged.

use std::io;

use daemon::control::{Command, KeyWanted, Outcome};

mod batch;

/// How the command line reaches the daemon: one request out, one answer back.
#[async_trait::async_trait]
pub trait Channel: Send + Sync {
    /// Sends one command and reads the answer.
    ///
    /// # Errors
    ///
    /// When the daemon cannot be reached, with the platform's own words for why.
    async fn ask(&self, command: Command) -> io::Result<Outcome>;
}

/// Where this machine keeps a signing key, and how it signs with one.
///
/// Asked only when the daemon has refused everything it could refuse, so a
/// prompt this shows belongs to an act that is going ahead.
pub trait Custody: Send + Sync {
    /// Makes the key the daemon asked for, and returns its public half. The
    /// platform's own prompt for protecting it is here.
    ///
    /// Where making the key unlocked it — a passphrase chosen a moment ago — the
    /// platform may hand it back unlocked, and the command line uses it for the
    /// daemon's **very next** answer only, if that answer is a batch for this
    /// key. Anything else and it is dropped at once.
    ///
    /// # Errors
    ///
    /// When no key was made, in words a person can act on.
    fn make_key(&self, wanted: &KeyWanted) -> Result<MadeKey, String>;

    /// Signs every message of a batch with the key named, where the platform
    /// asks the person — once, where the platform lets it be once.
    ///
    /// Called after the command line has printed every act in the batch. What
    /// the platform prints is *why* it is asking and how to refuse: where the
    /// key is held and what unlocks it.
    ///
    /// # Errors
    ///
    /// When nothing was signed — declined, refused, a wrong passphrase — in
    /// words. Nothing in the batch is signed then.
    fn sign_all(&self, asking: &Asking<'_>) -> Result<Vec<Vec<u8>>, String>;

    /// Whether this process may sign an administrative act at all: asked
    /// before an act that ends in a signature begins, where finding out at the
    /// signature would waste what came before — an invite, whose device has
    /// arrived and been shown a code by then.
    ///
    /// # Errors
    ///
    /// When it may not, in words a person can act on.
    fn may_sign(&self) -> Result<(), String> {
        Ok(())
    }
}

/// A batch about to be signed, as a platform needs it to ask.
#[derive(Debug, Clone, Copy)]
pub struct Asking<'a> {
    /// The name the key store knows the key by.
    pub key: &'a str,
    /// This machine's name for the network whose key it is, for saying whose
    /// passphrase is wanted.
    pub network: &'a str,
    /// The batch in one line, read off its bytes, for a platform prompt that can
    /// carry a line of its own.
    pub summary: &'a str,
    /// What to sign, in order.
    pub messages: &'a [&'a [u8]],
}

/// A key just made.
pub struct MadeKey {
    /// Its public half, for the daemon.
    pub public: Vec<u8>,
    /// The key itself, still unlocked from being made, where the platform has
    /// it that way — a passphrase-protected key the person chose the passphrase
    /// for a moment ago. `None` where the platform's own store asks on every use.
    pub unlocked: Option<Box<dyn Unlocked>>,
}

/// A signing key unlocked a moment ago, when it was made, and not yet put away.
///
/// Lives in one function of the command line for one answer of the daemon, and
/// is dropped there: never kept from one batch to the next, never stored.
pub trait Unlocked: Send {
    /// Signs every message without asking again.
    ///
    /// # Errors
    ///
    /// When a signature could not be made.
    fn sign_all(&self, messages: &[&[u8]]) -> Result<Vec<Vec<u8>>, String>;
}

/// A machine that cannot protect a signing key: it signs nothing, and says so.
///
/// Such a machine is a member of its networks and not an admin. Every act that
/// needs a key or a signature is refused here, before anything is made or
/// signed.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoCustody;

impl Custody for NoCustody {
    fn make_key(&self, _wanted: &KeyWanted) -> Result<MadeKey, String> {
        Err("this machine cannot protect a signing key, so none was made: it can be a member \
             of a network, and not an admin. Nothing was created."
            .to_owned())
    }

    fn sign_all(&self, _asking: &Asking<'_>) -> Result<Vec<Vec<u8>>, String> {
        Err("this machine cannot protect a signing key, so nothing was signed. Nothing changed."
            .to_owned())
    }

    fn may_sign(&self) -> Result<(), String> {
        Err("this machine cannot protect a signing key, so it signs no administrative act. \
             Nothing changed."
            .to_owned())
    }
}

/// What a platform adds of its own.
#[derive(Debug, Clone, Copy)]
pub struct Extras {
    /// Lines appended to the usage, for words the platform answers itself.
    pub usage: &'static str,
    /// What the usage says an act needs of whoever asks it: the platform's own
    /// word for acting on the machine — `Administrator` on Windows, `sudo` on
    /// Linux. A person reads it next to the command and has to know what to do.
    pub privileged: &'static str,
    /// Called after `status` prints, for what only this platform can say.
    pub after_status: fn(),
    /// Whether this process is an administrator, as the platform says: an
    /// elevated console on Windows, `root` on Linux. A word that needs one is
    /// refused before anything is asked of the daemon, which refuses it too.
    pub administrator: fn() -> bool,
}

impl Default for Extras {
    fn default() -> Self {
        Self { usage: "", privileged: "Administrator", after_status: || {}, administrator: || true }
    }
}

/// The words that take more than a network after them, each answered by a
/// path of its own in [`Cli::run`]. With [`Command::ALL`], every word a person
/// can type.
const WORDS_WITH_ARGUMENTS: &[&str] = &[
    "found",
    "join",
    "invite",
    "admit",
    "approve",
    "reject",
    "withdraw",
    "cancel",
    "expose",
    "unexpose",
    "exposed",
    "relay",
    "forget",
    "revoke",
    "set-anchors",
    "ipv4",
    "route",
    "rename",
];

/// The command line, with what the platform gave it.
pub struct Cli<'a> {
    /// How it reaches the daemon.
    pub channel: &'a dyn Channel,
    /// How it makes keys and signs.
    pub custody: &'a dyn Custody,
    /// The platform's additions.
    pub extras: Extras,
}

impl Cli<'_> {
    /// Sends one command and reads the answer.
    async fn ask(&self, command: Command) -> io::Result<Outcome> {
        // Refused because an invite for that name is still open: the two ways
        // on are said with the refusal.
        let invited = match &command {
            Command::Invite { name, .. } => Some(name.clone()),
            _ => None,
        };
        // Refused because something already waits: the way out is said with
        // the refusal, wherever this command prints it.
        self.channel.ask(command).await.map(|answer| match answer {
            Outcome::Failed { message, left_behind }
                if message.contains(daemon::control::INVITE_STILL_OPEN) =>
            {
                let name = daemon::control::shown(invited.as_deref().unwrap_or("<name>")).to_string();
                Outcome::Failed {
                    message: format!(
                        "{message}\n  what waits:      peerfectly pending\n  to withdraw it:  peerfectly withdraw {name}"
                    ),
                    left_behind,
                }
            }
            Outcome::Failed { message, left_behind }
                if message.contains(daemon::control::ALREADY_WAITING) =>
            {
                Outcome::Failed {
                    message: format!("{message}.\n  to cancel it:  peerfectly cancel"),
                    left_behind,
                }
            }
            other => other,
        })
    }

    /// Cancels what waits on this person: a join of this device's, by the name
    /// the pending list gives it, or the act stopped on a person — a founding
    /// or a move waiting on a relay's key. With nothing named and a single
    /// thing waiting, that one; with several joins, they are listed.
    async fn cancel_waiting(&self, named: Option<String>) -> std::process::ExitCode {
        use std::process::ExitCode;

        let list = match self.ask(Command::Pending { network: None }).await {
            Ok(Outcome::Pending(list)) => list,
            Ok(other) => return Self::said(other),
            Err(cause) => {
                eprintln!("{cause}");
                return ExitCode::FAILURE;
            }
        };
        let join = match named {
            Some(label) => Some(label),
            None if list.stopped.is_some() => None,
            None => match list.joins.as_slice() {
                [] => {
                    println!("nothing is waiting.");
                    return ExitCode::SUCCESS;
                }
                [only] => Some(only.label.clone()),
                several => {
                    eprintln!(
                        "this device is waiting in more than one join; name the one to cancel:"
                    );
                    for join in several {
                        eprintln!("  peerfectly cancel {}", join.label);
                    }
                    return ExitCode::FAILURE;
                }
            },
        };
        match join {
            Some(label) => match self.ask(Command::CancelJoin { label: label.clone() }).await {
                Ok(Outcome::Done) => {
                    println!(
                        "cancelled: the join `{label}` stopped waiting, and its keys are gone. If \
                         an admin approved it meanwhile, that device is in the network until an \
                         admin revokes it."
                    );
                    ExitCode::SUCCESS
                }
                Ok(other) => Self::said(other),
                Err(cause) => {
                    eprintln!("{cause}");
                    ExitCode::FAILURE
                }
            },
            None => {
                let what = list.stopped.unwrap_or_default();
                match self.ask(Command::Abandon).await {
                    Ok(Outcome::Done) => {
                        println!("cancelled: {what}. Nothing was signed.");
                        ExitCode::SUCCESS
                    }
                    Ok(other) => Self::said(other),
                    Err(cause) => {
                        eprintln!("{cause}");
                        ExitCode::FAILURE
                    }
                }
            }
        }
    }

    /// An answer that is not the one a command waits for, said as what it is.
    fn said(answer: Outcome) -> std::process::ExitCode {
        use std::process::ExitCode;

        match answer {
            Outcome::Declined { message }
            | Outcome::Failed { message, .. }
            | Outcome::NotAllowed { message } => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
            other => {
                eprintln!("unexpected answer from the daemon: {other:?}");
                ExitCode::FAILURE
            }
        }
    }

    /// Approves a request after showing it: the name it is admitted under and
    /// the one it proposed, its key's fingerprint, when it arrived, and the
    /// device already holding the name, if one does.
    async fn approve(&self, words: &[String]) -> std::process::ExitCode {
        use std::io::Write as _;
        use std::process::ExitCode;

        let (network, name, replace) = match Command::approval(words) {
            Ok(Command::Approve { network, name, replace }) => (network, name, replace),
            Ok(other) => {
                return Self::said(Outcome::Failed {
                    message: format!("not an approval: {other:?}"),
                    left_behind: Vec::new(),
                });
            }
            Err(refusal) => {
                eprintln!("{refusal}");
                return ExitCode::FAILURE;
            }
        };
        // Before anything is shown: a request this process cannot sign for is a
        // person's time spent on a review for nothing.
        if let Err(refusal) = self.custody.may_sign() {
            eprintln!("{refusal}");
            return ExitCode::FAILURE;
        }
        let list = match self.ask(Command::Pending { network: network.clone() }).await {
            Ok(Outcome::Pending(list)) => list,
            Ok(other) => return Self::said(other),
            Err(cause) => {
                eprintln!("{cause}");
                return ExitCode::FAILURE;
            }
        };
        let waiting = list.invites.iter().find(|line| {
            line.name == name
                && line.standing == "requested"
                && network.as_deref().is_none_or(|wanted| line.network == wanted)
        });
        let Some((line, request)) =
            waiting.and_then(|line| line.request.as_ref().map(|request| (line, request)))
        else {
            eprintln!(
                "no request for `{}` is waiting. `peerfectly pending` lists what is.",
                daemon::control::shown(&name)
            );
            return ExitCode::FAILURE;
        };

        println!();
        println!("  admitted as:        {}", daemon::control::shown(&line.name));
        println!("  the name it asked:  {}", daemon::control::shown(&request.proposed_name));
        println!("  its key:            {}", request.fingerprint);
        println!("  arrived:            {}", when(request.arrived_at));
        println!();
        println!("Anyone holding the invite could have made this request. If you are with the");
        println!("device's person, compare the key with the one its screen shows: they must be");
        println!("the same. If they differ, or you cannot tell this request is theirs, reject it.");
        println!();

        // A name this network already uses. Asked here, with the identifier the
        // decision falls on: a name is not an identity.
        let replacing = match (&request.taken, replace) {
            (None, _) => false,
            (Some(_), true) => true,
            (Some(held), false) => {
                println!(
                    "This network already has a device called {}: {}.",
                    daemon::control::shown(&held.name),
                    held.id
                );
                println!("Replacing revokes that device for good and gives the name to this one;");
                println!("otherwise this one is admitted under another name.");
                println!();
                print!("Replace it? [yes/no, no admits under another name] ");
                let _ = std::io::stdout().flush();
                said_yes()
            }
        };
        print!("Approve it? [yes/no] ");
        let _ = std::io::stdout().flush();
        if !said_yes() {
            eprintln!("nothing was signed; the request is still waiting.");
            return ExitCode::FAILURE;
        }
        let asked = Command::Approve { network, name, replace: replacing };
        let answer = self.ask_and_sign(asked.clone()).await;
        self.shown(&asked, answer)
    }

    /// Asks a join to begin, and says what is next. It returns at once: the
    /// device waits on its own, across restarts, until it is admitted or the
    /// join is cancelled.
    async fn join(&self, command: Command) -> std::process::ExitCode {
        use std::process::ExitCode;

        match self.ask_and_sign(command).await {
            Ok(Outcome::JoinStarted { label, fingerprint, conflicts }) => {
                println!();
                println!("asked to join. This device waits for the admin that invited it.");
                println!();
                println!("  its key:  {fingerprint}");
                println!();
                // Said now, and sent with the request: the admin approving it
                // may move the network.
                if !conflicts.is_empty() {
                    println!("the network's IPv4 addresses coincide with what this device holds:");
                    for conflict in &conflicts {
                        println!("  {}", daemon::control::shown(conflict));
                    }
                    println!("the admin is told with the request. Until the network moves, the");
                    println!("devices at those addresses are reached here by IPv6 only.");
                    println!();
                }
                println!("If you are with the admin, compare it with the key their pending list");
                println!(
                    "shows before they approve. Nothing else is needed here: this device joins"
                );
                println!("on its own once it is approved, even after a restart.");
                println!();
                println!("  where it stands:   peerfectly pending");
                println!("  to stop waiting:   peerfectly cancel {label}");
                ExitCode::SUCCESS
            }
            Ok(other) => Self::said(other),
            Err(cause) => {
                eprintln!("{cause}");
                ExitCode::FAILURE
            }
        }
    }

    /// Issues an invite and shows it. The command ends there: the daemon dials
    /// the device it brings, keeps its request, and lists it for approval.
    async fn invite_through_the_daemon(&self, command: Command) -> std::process::ExitCode {
        use std::process::ExitCode;

        // Before anything is issued: a request this process cannot sign for is a
        // person's time and an approval that cannot happen.
        if let Err(refusal) = self.custody.may_sign() {
            eprintln!("{refusal}");
            return ExitCode::FAILURE;
        }
        match self.ask(command).await {
            Ok(Outcome::Invited { invite, scannable, name, expires_at }) => {
                let name = daemon::control::shown(&name).to_string();
                println!();
                println!("{scannable}");
                println!("an invite for {name}. On that device, run:");
                println!();
                println!("  peerfectly join {invite}");
                println!();
                println!("or scan the code above. It is open {}.", open_for(expires_at));
                println!();
                println!(
                    "Anyone holding the invite can make the request it opens, so send it only"
                );
                println!("to that device's person. This machine takes the request on its own; you");
                println!("approve it when you choose:");
                println!();
                println!("  what waits:      peerfectly pending");
                println!("  to approve it:   peerfectly approve {name}");
                println!("  to withdraw it:  peerfectly withdraw {name}");
                ExitCode::SUCCESS
            }
            Ok(other) => Self::said(other),
            Err(cause) => {
                eprintln!("{cause}");
                ExitCode::FAILURE
            }
        }
    }

    /// Makes the signing key the daemon asked for, and tells it the key exists.
    ///
    /// Hands back the daemon's answer, and the key still unlocked where the
    /// platform made it that way.
    async fn make_the_key(
        &self,
        wanted: &KeyWanted,
    ) -> Result<(Outcome, Option<Box<dyn Unlocked>>), String> {
        let made = self.custody.make_key(wanted)?;
        let answer = self
            .ask(Command::KeyMade { id: wanted.id.clone(), public: made.public })
            .await
            .map_err(|cause| {
                format!("the key was made and the daemon could not be told: {cause}")
            })?;
        Ok((answer, made.unlocked))
    }

    /// Answers the words this process was started with, as `peerfectly` does.
    #[must_use]
    pub fn run(&self) -> std::process::ExitCode {
        use std::process::ExitCode;

        use daemon::control::Command;

        let Some(word) = std::env::args().nth(1) else {
            eprintln!("{}{}", usage(self.extras.privileged), self.extras.usage);
            return ExitCode::FAILURE;
        };

        // Refused before anything starts, by the rule the daemon applies: a
        // person finds out at the first word, not after an act has begun.
        let known = Command::ALL.iter().any(|(each, _)| *each == word)
            || WORDS_WITH_ARGUMENTS.contains(&word.as_str());
        if known && Command::word_needs_an_administrator(&word) && !(self.extras.administrator)() {
            eprintln!(
                "`peerfectly {word}` needs {}. Nothing was asked of the daemon.",
                self.extras.privileged
            );
            return ExitCode::FAILURE;
        }

        // Founding happens here rather than over the pipe. There is no daemon to
        // ask: it reads a roster and stops without one, so the network has to exist
        // before it can run at all.
        // Founding and joining go through the daemon now, for the reason admitting
        // always did: the daemon holds the roster, and an operation appended to the
        // log by another process is invisible to it until it restarts. That restart
        // is what these two used to require.
        if word == "found" || word == "join" {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            let built = if word == "found" { founding_from(&rest) } else { joining_from(&rest) };
            let command = match built {
                Ok(command) => command,
                Err(refusal) => {
                    eprintln!("{refusal}");
                    return ExitCode::FAILURE;
                }
            };
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(cause) => {
                    eprintln!("could not start: {cause}");
                    return ExitCode::FAILURE;
                }
            };
            if word == "join" {
                return runtime.block_on(self.join(command));
            }
            return runtime.block_on(self.enrol_through_the_daemon(command));
        }

        // Approving shows the request first, and asks.
        if word == "approve" {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(cause) => {
                    eprintln!("could not start: {cause}");
                    return ExitCode::FAILURE;
                }
            };
            return runtime.block_on(self.approve(&rest));
        }

        // Inviting goes through the daemon, because the daemon holds the roster: an
        // operation appended by another process would be invisible to it until it
        // restarted, and a device admitted into a roster nobody is using cannot
        // connect. And the daemon is what goes on dialling the invited device
        // once this command has ended.
        if word == "invite" {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            let command = match inviting_from(&rest) {
                Ok(command) => command,
                Err(refusal) => {
                    eprintln!("{refusal}");
                    return ExitCode::FAILURE;
                }
            };
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(cause) => {
                    eprintln!("could not start: {cause}");
                    return ExitCode::FAILURE;
                }
            };
            return runtime.block_on(self.invite_through_the_daemon(command));
        }

        // Admitting a batch file: read here, reviewed, and signed with one consent.
        if word == "admit" {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(cause) => {
                    eprintln!("could not start: {cause}");
                    return ExitCode::FAILURE;
                }
            };
            return runtime.block_on(self.admit_batch(&rest));
        }

        // Dropping what waits on this person: a join of this device's, or a
        // founding or a move stopped on a relay's key.
        if word == "cancel" {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(cause) => {
                    eprintln!("could not start: {cause}");
                    return ExitCode::FAILURE;
                }
            };
            return runtime.block_on(self.cancel_waiting(std::env::args().nth(2)));
        }

        // Opening a port to one network, closing it, and listing what is open.
        if word == "expose" || word == "unexpose" || word == "exposed" {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            let command = if word == "exposed" {
                match rest.as_slice() {
                    [] => Ok(daemon::control::Command::Exposed { network: None }),
                    [network] => {
                        Ok(daemon::control::Command::Exposed { network: Some(network.clone()) })
                    }
                    _ => Err(format!("usage: {}", daemon::control::Command::EXPOSE_USAGE)),
                }
            } else {
                daemon::control::Command::exposure(&word, &rest)
            };
            let command = match command {
                Ok(command) => command,
                Err(refusal) => {
                    eprintln!("{refusal}");
                    return ExitCode::FAILURE;
                }
            };
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(cause) => {
                    eprintln!("could not start: {cause}");
                    return ExitCode::FAILURE;
                }
            };
            return runtime.block_on(self.exposing(command));
        }

        // Moving a relay takes arguments and a person in the middle, like founding.
        if word == "relay" {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            let command = match daemon::control::Command::relay_change(&rest) {
                Ok(command) => command,
                Err(refusal) => {
                    eprintln!("{refusal}");
                    return ExitCode::FAILURE;
                }
            };
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(cause) => {
                    eprintln!("could not start: {cause}");
                    return ExitCode::FAILURE;
                }
            };
            return runtime.block_on(self.move_relay(command));
        }

        // Revoking takes arguments, so it is not one of the single words `parse`
        // knows. It still goes through the daemon: the daemon holds the roster, and
        // a revocation appended by another process would leave the running node
        // still talking to the device it had just expelled.
        let command = if word == "forget" {
            // Removing a network from this device, carried or not, with its
            // directory and every key kept for it wherever it is kept. Local: the
            // other devices are owed a revocation, which only an admin can sign,
            // so this says so before it asks. The daemon refuses while an
            // enrolment for it is open, and asks again — `OnlyAdmin` — when this
            // device is its only admin.
            let Some(label) = std::env::args().nth(2) else {
                eprintln!("usage: {FORGET_USAGE}");
                return ExitCode::FAILURE;
            };
            // Said before it happens, because both halves are things a person
            // removing a network is likely to have wrong.
            println!();
            println!(
                "Removing `{label}` from this device:",
                label = daemon::control::shown(&label)
            );
            println!();
            println!("  · the keys in it go with it. This device cannot rejoin that network under");
            println!("    the identity it is throwing away — joining again makes a new one.");
            println!(
                "  · the network is told nothing. The other devices go on listing this device"
            );
            println!("    until an administrator revokes it.");
            println!();
            println!("Removing is not leaving.");
            println!();
            print!("Remove it? [yes/no] ");
            let _ = std::io::Write::flush(&mut std::io::stdout());
            let mut answer = String::new();
            let agreed = std::io::stdin().read_line(&mut answer).is_ok()
                && matches!(answer.trim().to_ascii_lowercase().as_str(), "yes" | "y");
            if !agreed {
                eprintln!("nothing was removed.");
                return ExitCode::FAILURE;
            }
            daemon::control::Command::Forget { label, last_admin: false }
        } else if word == "revoke" {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            match daemon::control::Command::revocation(&rest) {
                Ok(command) => command,
                Err(refusal) => {
                    eprintln!("{refusal}");
                    return ExitCode::FAILURE;
                }
            }
        } else if word == "withdraw" || word == "reject" {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            let read = if word == "withdraw" {
                daemon::control::Command::withdrawal(&rest)
            } else {
                daemon::control::Command::rejection(&rest)
            };
            match read {
                Ok(command) => command,
                Err(refusal) => {
                    eprintln!("{refusal}");
                    return ExitCode::FAILURE;
                }
            }
        } else if word == "set-anchors" {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            match daemon::control::Command::anchors_setting(&rest) {
                Ok(command) => command,
                Err(refusal) => {
                    eprintln!("{refusal}");
                    return ExitCode::FAILURE;
                }
            }
        } else if word == "route" {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            match daemon::control::Command::route_act(&rest) {
                Ok(command) => command,
                Err(refusal) => {
                    eprintln!("{refusal}");
                    return ExitCode::FAILURE;
                }
            }
        } else if word == "ipv4" {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            match daemon::control::Command::ipv4_act(&rest) {
                Ok(command) => command,
                Err(refusal) => {
                    eprintln!("{refusal}");
                    return ExitCode::FAILURE;
                }
            }
        } else if word == "rename" {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            match daemon::control::Command::renaming(&rest) {
                Ok(command) => command,
                Err(refusal) => {
                    eprintln!("{refusal}");
                    return ExitCode::FAILURE;
                }
            }
        } else {
            // A second word, where the command takes one, is the network it acts on.
            // A person holding one network types neither it nor anything in its
            // place; a person holding several is refused by the daemon until they do.
            let network = if Command::takes_a_network(&word) {
                std::env::args().nth(2).filter(|first| !first.starts_with('-'))
            } else {
                None
            };
            match Command::parse(&word, network) {
                Ok(command) => command,
                Err(unknown) => {
                    // Absent, not broken. A command that does not exist must not
                    // read like one that failed.
                    eprintln!("{unknown}");
                    return ExitCode::FAILURE;
                }
            }
        };

        let runtime = match tokio::runtime::Runtime::new() {
            Ok(runtime) => runtime,
            Err(cause) => {
                eprintln!("could not start: {cause}");
                return ExitCode::FAILURE;
            }
        };

        // Which view the answer is drawn as. The daemon answers all three with the
        // same report — one gathering, one code path — and what differs is the
        // question being asked: what do I hold, who else is in it, what is my
        // address.
        let asked = command.clone();
        runtime.block_on(async move {
            // Through the wrapper, not through `ask`: any command may turn out to
            // need a signature this process must obtain, and keying that on a list
            // of which ones do is how a command added later comes to be the one that
            // does not work.
            let answer = self.ask_and_sign(command).await;
            let answer = self.when_only_admin(answer, said_yes).await;
            let answer = self.when_voiding(&asked, answer, said_yes).await;
            // `peers` lists every device, a page at a time: the report holds
            // the first of each network, and the rest are asked as they are
            // drawn, so that neither end holds a million at once.
            let continuing = match (&asked, &answer) {
                (Command::Peers { network, .. }, Ok(Outcome::Reported(report))) => {
                    report.peers_continuing(network.as_deref())
                }
                _ => Vec::new(),
            };
            let code = self.shown(&asked, answer);
            for (label, after) in continuing {
                if !self.rest_of_peers(&label, after).await {
                    return std::process::ExitCode::FAILURE;
                }
            }
            code
        })
    }

    /// Draws a network's devices after the report's first page, a page at a
    /// time, until the last. Whether every page was read.
    async fn rest_of_peers(&self, label: &str, mut after: String) -> bool {
        println!();
        println!("{label}, continued");
        loop {
            let asked = Command::Peers { network: Some(label.to_owned()), after: Some(after) };
            match self.ask(asked).await {
                Ok(Outcome::Peers(page)) => {
                    print!("{}", daemon::views::PeerRows(&page.peers));
                    match page.after {
                        Some(next) => after = next,
                        None => return true,
                    }
                }
                Ok(Outcome::Failed { message, .. }) => {
                    eprintln!("the rest of `{label}`'s devices could not be read: {message}");
                    return false;
                }
                Ok(_) => {
                    eprintln!("the rest of `{label}`'s devices could not be read");
                    return false;
                }
                Err(cause) => {
                    eprintln!("the rest of `{label}`'s devices could not be read: {cause}");
                    return false;
                }
            }
        }
    }

    /// Puts the question a revocation that voids acts asks, before anything is
    /// signed, and sends it again with the acknowledgement on yes.
    async fn when_voiding(
        &self,
        asked: &Command,
        answer: io::Result<Outcome>,
        agrees: fn() -> bool,
    ) -> io::Result<Outcome> {
        let Ok(Outcome::WouldVoid { voids, .. }) = &answer else { return answer };
        let Command::Revoke { network, target, reason } = asked else { return answer };
        println!();
        println!("Before anything is signed: {voids}.");
        println!();
        println!("Acts an admin signed concurrently with its removal lose their effect, and");
        println!("this device cannot keep these. Whoever they admitted or changed is as before.");
        println!();
        print!("Revoke anyway? [yes/no] ");
        if !agrees() {
            return Ok(Outcome::Declined { message: "nothing was signed.".to_owned() });
        }
        let voiding = Command::RevokeVoiding {
            network: network.clone(),
            target: target.clone(),
            reason: reason.clone(),
        };
        self.ask_and_sign_as(voiding, asked).await
    }

    /// Puts the only admin's question where the daemon asked for it, and sends
    /// the removal again on yes.
    ///
    /// A person discovers they are a network's only admin when they are told,
    /// so the question belongs here rather than in a flag they would have had
    /// to know about. `agrees` reads the answer, and is a parameter so a test
    /// can answer for the person.
    async fn when_only_admin(
        &self,
        answer: io::Result<Outcome>,
        agrees: fn() -> bool,
    ) -> io::Result<Outcome> {
        let Ok(Outcome::OnlyAdmin { network }) = &answer else { return answer };
        let network = network.clone();
        println!();
        println!(
            "This device is the only admin of `{}`. Once it is removed, nobody will be able to",
            daemon::control::shown(&network)
        );
        println!("admit or revoke anything in it — a stolen device included.");
        println!();
        print!("Remove it anyway? [yes/no] ");
        if !agrees() {
            return Ok(Outcome::Declined { message: "nothing was removed.".to_owned() });
        }
        self.ask_and_sign(Command::Forget { label: network, last_admin: true }).await
    }

    /// What an answer to a single command shows, and how the process exits.
    ///
    /// **Every answer that is not a success says so.** A refusal for want of
    /// authority printed nothing and exited 0 here once — found by the Linux
    /// testbed, where `bob` asked the daemon to stop and was told nothing — and a
    /// refusal that reads as success is worse than one that reads as a failure.
    fn shown(
        &self,
        asked: &daemon::control::Command,
        answer: io::Result<daemon::control::Outcome>,
    ) -> std::process::ExitCode {
        use std::process::ExitCode;

        use daemon::control::{Command, Outcome};

        match answer {
            Ok(Outcome::Reported(report)) => {
                match asked {
                    Command::Peers { network, .. } => {
                        print!("{}", report.peers(network.as_deref()))
                    }
                    Command::Address { network } => {
                        print!("{}", report.address(network.as_deref()));
                    }
                    _ => {
                        print!("{report}");
                        // **This is the surface that finds them.** The daemon runs
                        // as the machine and cannot even name a person's own
                        // directory; this runs as the person, and theirs is the
                        // one the networks are in.
                        (self.extras.after_status)();
                    }
                }
                ExitCode::SUCCESS
            }
            Ok(Outcome::Done) => {
                match asked {
                    Command::Withdraw { name, .. } => println!(
                        "withdrawn: the invite for {} takes no request now.",
                        daemon::control::shown(name)
                    ),
                    Command::Reject { name, .. } => println!(
                        "rejected: nothing was signed, and the invite for {} takes no other \
                         request.",
                        daemon::control::shown(name)
                    ),
                    _ => {}
                }
                ExitCode::SUCCESS
            }
            Ok(Outcome::Pending(list)) => {
                print!("{}", pending_listed(&list));
                ExitCode::SUCCESS
            }
            Ok(Outcome::Declined { message }) => {
                // Nothing was signed; a person said no. Not a failure, and not a success.
                eprintln!("{message}");
                ExitCode::FAILURE
            }
            Ok(Outcome::Failed { message, left_behind }) => {
                eprintln!("{message}");
                for item in left_behind {
                    eprintln!("  still installed: {item}");
                }
                ExitCode::FAILURE
            }
            Ok(Outcome::NotAllowed { message }) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
            // Reached only if the question was not put; nothing was signed.
            Ok(Outcome::WouldVoid { voids, .. }) => {
                eprintln!("nothing was signed: {voids}.");
                ExitCode::FAILURE
            }
            // Reached only if the question was not put; nothing was removed.
            Ok(Outcome::OnlyAdmin { network }) => {
                eprintln!(
                    "`{}` was not removed: this device is its only admin.",
                    daemon::control::shown(&network)
                );
                ExitCode::FAILURE
            }
            Err(cause) => {
                eprintln!("{cause}");
                ExitCode::FAILURE
            }
            Ok(_) => ExitCode::SUCCESS,
        }
    }

    /// Sends a command, and answers any signatures it turns out to need.
    ///
    /// The daemon holds the roster and prepares what must be signed; it cannot sign,
    /// because the key is where only the person sitting here can reach it. So an
    /// act can come back unfinished, and finishing it is this.
    async fn ask_and_sign(
        &self,
        command: daemon::control::Command,
    ) -> std::io::Result<daemon::control::Outcome> {
        let expected = command.clone();
        self.ask_and_sign_as(command, &expected).await
    }

    /// The same, where what is sent is a confirmation and the act it confirms is
    /// `expected` — what the person typed, for checking the bytes against.
    ///
    /// # One act, one batch, one asking
    ///
    /// Everything an act needs signed arrives together: founding's genesis and
    /// first snapshot, a replacement's revocation and admission, an act and the
    /// snapshot the network is then owed. It is checked to hold together, shown
    /// whole — every act, read off its bytes, with what follows from it — and
    /// signed at once, so a person authorises what they have seen rather than the
    /// first of several things they have not.
    ///
    /// It still loops, because the daemon's answer to a batch, or to a key made,
    /// can be another request: a founding makes its key and then asks for the
    /// batch that key signs.
    async fn ask_and_sign_as(
        &self,
        command: daemon::control::Command,
        expected: &daemon::control::Command,
    ) -> std::io::Result<daemon::control::Outcome> {
        use daemon::control::{Command, Outcome};

        let mut outcome = self.ask(command).await?;
        // A key made a moment ago, still unlocked, kept for the daemon's very
        // next answer and no longer: taken out at the top of every turn and
        // dropped at the end of it unless that answer was a batch for it.
        let mut just_made: Option<(String, Box<dyn Unlocked>)> = None;
        loop {
            let made = just_made.take();

            // **The key is made here, not in the daemon.** The key store asks a
            // person before it will protect one, and asking needs a desktop the
            // daemon does not have — it is the same reason the signature is obtained
            // here, one step earlier. The daemon has already refused everything it
            // could refuse, so the prompt belongs to an act that is going ahead.
            if let Outcome::NeedsKey(wanted) = outcome {
                outcome = match self.make_the_key(&wanted).await {
                    Ok((answered, unlocked)) => {
                        just_made = unlocked.map(|key| (wanted.name.clone(), key));
                        answered
                    }
                    // Returned, not printed: every caller prints what it is given.
                    Err(refusal) => {
                        return Ok(Outcome::Failed { message: refusal, left_behind: Vec::new() });
                    }
                };
                continue;
            }

            let Outcome::NeedsSignatures(wanted) = outcome else { return Ok(outcome) };

            // Whether this is one act this command signs, read off the bytes. A
            // batch that is not is refused whole, and the daemon is told at once
            // rather than left holding it.
            let read = match batch::holds_together(expected, &wanted) {
                Ok(read) => read,
                Err(why) => {
                    let _ = self.ask(Command::NotSigned { id: wanted.id }).await;
                    let message = format!("{why}. Nothing was signed.");
                    return Ok(Outcome::Failed { message, left_behind: Vec::new() });
                }
            };

            println!();
            print!("{}", batch::listed(&read, &wanted.network, expected));
            println!();

            let messages: Vec<&[u8]> =
                wanted.items.iter().map(|item| item.message.as_slice()).collect();
            let signed = match made {
                Some((name, key)) if name == wanted.key => {
                    println!("signing with the key you have just made, without asking again.");
                    key.sign_all(&messages)
                }
                _ => {
                    let summary = batch::summary(&read, &wanted.network, expected);
                    self.custody.sign_all(&Asking {
                        key: &wanted.key,
                        network: &wanted.network,
                        summary: &summary,
                        messages: &messages,
                    })
                }
            };

            let signatures = match signed {
                Ok(signatures) if signatures.len() == messages.len() => signatures,
                Ok(_) => {
                    let _ = self.ask(Command::NotSigned { id: wanted.id }).await;
                    return Ok(Outcome::Failed {
                        message: "the key store did not sign every item, so nothing was signed"
                            .to_owned(),
                        left_behind: Vec::new(),
                    });
                }
                // Told at once rather than left to expire: the act is over the
                // moment a person declines, and the daemon should stop holding it.
                Err(refusal) => {
                    let _ = self.ask(Command::NotSigned { id: wanted.id }).await;
                    return Ok(Outcome::Declined { message: refusal });
                }
            };

            outcome = self.ask(Command::Signed { id: wanted.id, signatures }).await?;
        }
    }

    /// Asks for a port to be opened or closed, or for what is open, and prints it.
    async fn exposing(&self, command: daemon::control::Command) -> std::process::ExitCode {
        use std::process::ExitCode;

        use daemon::control::Outcome;

        match self.ask(command).await {
            Ok(Outcome::Exposed { rules }) => {
                if rules.is_empty() {
                    println!("nothing is exposed.");
                }
                for rule in rules {
                    println!(
                        "{}  {} {}",
                        daemon::control::shown(&rule.network),
                        rule.protocol.word(),
                        rule.port
                    );
                }
                ExitCode::SUCCESS
            }
            Ok(
                Outcome::Declined { message }
                | Outcome::Failed { message, .. }
                | Outcome::NotAllowed { message },
            ) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
            Ok(other) => {
                eprintln!("unexpected answer from the daemon: {other:?}");
                ExitCode::FAILURE
            }
            Err(cause) => {
                eprintln!("{cause}");
                ExitCode::FAILURE
            }
        }
    }

    /// Moves a network to another relay, with a person confirming what it costs.
    ///
    /// An immediate move is confirmed **before anything is sent**, and separately
    /// from the relay's key: it loses every device switched off right now, and a
    /// person must say yes to that as its own question rather than as part of
    /// another one.
    async fn move_relay(&self, command: daemon::control::Command) -> std::process::ExitCode {
        use std::process::ExitCode;

        use daemon::control::{Command, Outcome};

        if let Command::ChangeRelay { immediately: true, .. } = &command {
            println!();
            println!("Moving at once, with no transition.");
            println!();
            println!("Every device switched off right now will not find this network again:");
            println!("it knows only the relay being left, and nobody will be there. Each of");
            println!("them will have to join again.");
            println!();
            println!("Without --now, everybody stays on the old relay for one freshness window,");
            println!("so a device that comes back in that time follows the move by itself.");
            println!();
            print!("Move at once anyway? [yes/no] ");
            if !said_yes() {
                println!("nothing was changed.");
                return ExitCode::FAILURE;
            }
        }

        let expected = command.clone();
        let answered = match self.ask_and_sign(command).await {
            Ok(Outcome::ConfirmingRelay { relay, key, .. }) => {
                if !key_confirmed(&relay, &key) {
                    let _ = self.ask(Command::Abandon).await;
                    println!("nothing was signed.");
                    return ExitCode::FAILURE;
                }
                self.ask_and_sign_as(Command::Confirm, &expected).await
            }
            other => other,
        };

        match answered {
            Ok(Outcome::Reported(report)) => {
                print!("{report}");
                println!();
                println!("the relay was changed. Keep the old relay running until the move ends —");
                println!("`status` says when.");
                ExitCode::SUCCESS
            }
            Ok(Outcome::Declined { message } | Outcome::Failed { message, .. }) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
            Ok(Outcome::NotAllowed { message }) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
            Ok(other) => {
                eprintln!("unexpected answer from the daemon: {other:?}");
                ExitCode::FAILURE
            }
            Err(cause) => {
                eprintln!("{cause}");
                ExitCode::FAILURE
            }
        }
    }

    /// Runs a founding or a join to its end, with a person in the middle.
    ///
    /// Both have the same shape: a command starts something, the daemon reports what
    /// a person has to look at, and a confirmation finishes it. The waiting happens
    /// here because a person is already standing here — the control channel stays one
    /// request and one answer.
    async fn enrol_through_the_daemon(
        &self,
        command: daemon::control::Command,
    ) -> std::process::ExitCode {
        use std::process::ExitCode;

        use daemon::control::{Command, Outcome};

        let expected = command.clone();
        let started = match self.ask_and_sign(command).await {
            Ok(outcome) => outcome,
            Err(cause) => {
                eprintln!("{cause}");
                return ExitCode::FAILURE;
            }
        };

        match started {
            // Founding with nothing to look at: already done.
            Outcome::Reported(report) => {
                print!("{report}");
                println!();
                println!("founded. this device is an admin of its own network.");
                println!();
                println!("next:");
                println!("  invite a device:  peerfectly invite <its name>");
                ExitCode::SUCCESS
            }

            // A relay key nobody has vouched for, waiting on a person.
            Outcome::ConfirmingRelay { relay, key, .. } => {
                if !key_confirmed(&relay, &key) {
                    let _ = self.ask(Command::Abandon).await;
                    println!("nothing was signed.");
                    return ExitCode::FAILURE;
                }
                self.finish(&expected).await
            }

            Outcome::Declined { message } | Outcome::Failed { message, .. } => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
            other => {
                eprintln!("unexpected answer from the daemon: {other:?}");
                ExitCode::FAILURE
            }
        }
    }

    /// Confirms whatever is waiting, and says what came of it.
    ///
    /// `expected` is the act the confirmation finishes, which is what the bytes
    /// are checked against.
    async fn finish(&self, expected: &daemon::control::Command) -> std::process::ExitCode {
        use std::process::ExitCode;

        use daemon::control::{Command, Outcome};

        match self.ask_and_sign_as(Command::Confirm, expected).await {
            Ok(Outcome::Reported(report)) => {
                print!("{report}");
                println!();
                println!("founded. this device is an admin of its own network.");
                ExitCode::SUCCESS
            }
            Ok(Outcome::Declined { message }) | Ok(Outcome::Failed { message, .. }) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
            Ok(other) => {
                eprintln!("unexpected answer from the daemon: {other:?}");
                ExitCode::FAILURE
            }
            Err(cause) => {
                eprintln!("{cause}");
                ExitCode::FAILURE
            }
        }
    }

    /// Admits a batch file: reads it, hands it to the daemon in parts, shows
    /// what it would do, and on one yes has it signed.
    async fn admit_batch(&self, words: &[String]) -> std::process::ExitCode {
        use std::process::ExitCode;

        use daemon::control::{BatchFile, Command, Outcome};

        let asked = match admitting_from(words) {
            Ok(asked) => asked,
            Err(refusal) => {
                eprintln!("{refusal}");
                return ExitCode::FAILURE;
            }
        };
        let text = match std::fs::read_to_string(&asked.file) {
            Ok(text) => text,
            Err(cause) => {
                eprintln!("{}: {cause}", asked.file);
                return ExitCode::FAILURE;
            }
        };
        let file = match BatchFile::read(&text) {
            Ok(file) => file,
            Err(refusal) => {
                eprintln!("{refusal}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(refusal) = self.custody.may_sign() {
            eprintln!("{refusal}");
            return ExitCode::FAILURE;
        }

        // In parts, each well within what one command may carry.
        for part in file.devices.chunks(BATCH_PART) {
            let staging =
                Command::StageBatch { network: asked.network.clone(), devices: part.to_vec() };
            match self.ask(staging).await {
                Ok(Outcome::Staged { .. }) => {}
                Ok(Outcome::Declined { message } | Outcome::Failed { message, .. }) => {
                    eprintln!("{message}");
                    return ExitCode::FAILURE;
                }
                Ok(other) => {
                    eprintln!("unexpected answer from the daemon: {other:?}");
                    return ExitCode::FAILURE;
                }
                Err(cause) => {
                    eprintln!("{cause}");
                    return ExitCode::FAILURE;
                }
            }
        }

        let admit = |reviewed: Option<Vec<String>>| Command::AdmitBatch {
            network: asked.network.clone(),
            label: file.label.clone(),
            light: asked.light,
            groups: asked.groups.clone(),
            ipv6_only: asked.ipv6_only,
            reviewed,
        };
        let review = match self.ask(admit(None)).await {
            Ok(Outcome::BatchReview { network, count, label, mode, groups, block, skipped }) => {
                println!();
                println!(
                    "{network}: admit a batch of {count} devices, `{}`",
                    daemon::control::shown(&label)
                );
                println!("  mode        {mode}");
                println!(
                    "  groups      {}",
                    if groups.is_empty() { "none".to_owned() } else { groups.join(", ") }
                );
                println!("  addresses   {}", block.unwrap_or_else(|| "none: IPv6 only".to_owned()));
                if skipped.is_empty() {
                    println!("  skipped     none");
                } else {
                    println!("  skipped     {} of them, which will have no effect:", skipped.len());
                    for line in &skipped {
                        let name = daemon::control::shown(&line.name).to_string();
                        println!("    {name:<24} {}", line.why);
                    }
                }
                println!();
                print!("Admit this batch? [yes/no] ");
                skipped.into_iter().map(|line| line.name).collect::<Vec<_>>()
            }
            Ok(Outcome::Declined { message } | Outcome::Failed { message, .. }) => {
                let _ = self.ask(Command::Abandon).await;
                eprintln!("{message}");
                return ExitCode::FAILURE;
            }
            Ok(other) => {
                eprintln!("unexpected answer from the daemon: {other:?}");
                return ExitCode::FAILURE;
            }
            Err(cause) => {
                eprintln!("{cause}");
                return ExitCode::FAILURE;
            }
        };
        if !said_yes() {
            let _ = self.ask(Command::Abandon).await;
            eprintln!("nothing was signed.");
            return ExitCode::FAILURE;
        }
        let command = admit(Some(review));
        let expected = command.clone();
        match self.ask_and_sign_as(command, &expected).await {
            Ok(Outcome::Reported(report)) => {
                print!("{report}");
                println!();
                println!("admitted. Each board joins at its next attempt.");
                ExitCode::SUCCESS
            }
            Ok(Outcome::Declined { message } | Outcome::Failed { message, .. }) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
            Ok(_) => ExitCode::SUCCESS,
            Err(cause) => {
                eprintln!("{cause}");
                ExitCode::FAILURE
            }
        }
    }
}

/// Builds the founding command from what a person typed.
///
/// The parsing stays here — it is what a terminal is for — and the work goes to
/// the daemon. A relay given as its host is asked for its key there, because
/// that is the process that will use it and because doing it here would mean
/// two processes talking to the relay's host about the same thing.
fn founding_from(rest: &[String]) -> Result<daemon::control::Command, String> {
    use daemon::control::Command;

    // The network's name, which is this machine's own name for it. The device's
    // own name is separate and has a sensible default; the network's does not,
    // because it is the word a person will type at every later command.
    let label = rest
        .first()
        .filter(|word| !word.starts_with("--"))
        .ok_or_else(|| format!("usage: {FOUND_USAGE}"))?
        .clone();
    let name = device_name(rest)?;

    // An option found does not take is refused, rather than ignored and found
    // out later.
    if let Some(unknown) =
        rest.iter().find(|word| word.starts_with("--") && !FOUND_OPTIONS.contains(&word.as_str()))
    {
        return Err(format!("`{unknown}` is not an option of found.\nusage: {FOUND_USAGE}"));
    }

    // Read here as the daemon will read it, so a form it would refuse is refused
    // before it is asked anything. The daemon reads it again: the Android app is
    // held to the same.
    let relay_address = option(rest, "--relay");
    if let Some(relay) = relay_address.as_deref() {
        daemon::relay::Given::read(relay)?;
    }

    // Read here as well as in the daemon, so a range that is not allowed is
    // refused before the daemon is asked anything, and a range that is allowed
    // is said out loud: it moves every device's IPv4 address, and software that
    // predates it cannot read the network.
    let ipv4_range = option(rest, "--ipv4-range");
    if let Some(range) = daemon::founding::ipv4_range(ipv4_range.as_deref())? {
        println!("every device in this network holds its IPv4 address in {range}.");
        println!();
    }
    // Without a block named, the daemon proposes one this size, and the status
    // after says which.
    let devices = match option(rest, "--devices") {
        Some(count) => {
            Some(count.parse::<u32>().ok().filter(|count| *count > 0).ok_or_else(|| {
                format!("`{count}` is not a number of devices. Nothing was signed.")
            })?)
        }
        None => None,
    };
    if ipv4_range.is_some() && devices.is_some() {
        return Err(format!(
            "--ipv4-range names the block, --devices asks for one to be proposed: one or the \
             other.\nusage: {FOUND_USAGE}"
        ));
    }

    // None unless asked for, and said what it buys when it is.
    let window_days = match option(rest, "--window") {
        Some(days) => {
            let days: u32 =
                days.parse().ok().filter(|days| *days > 0).ok_or_else(|| {
                    format!("`{days}` is not a number of days. Nothing was signed.")
                })?;
            println!("a freshness window of {days} days: {WINDOW_SENTENCE}");
            println!();
            Some(days)
        }
        None => None,
    };

    Ok(Command::Found {
        label: label.clone(),
        name,
        // Composed from the network's own name so that two networks on one
        // machine do not both land on a default and collide. A **proposal**: the
        // suffix is a signed network parameter, and `--suffix` is taken exactly
        // as given. The label is brought into the roster's grammar where it can
        // be; where it cannot, the person is asked rather than given a name they
        // did not choose.
        suffix: match option(rest, "--suffix") {
            Some(given) => given,
            None => daemon::founding::suffix_under(&label).ok_or_else(|| {
                format!(
                    "`{label}` cannot be turned into a network suffix. Say one with --suffix, \
                     such as --suffix casa.internal. Nothing was signed."
                )
            })?,
        },
        relay: relay_address,
        ipv4_range,
        devices,
        window_days,
    })
}

/// Builds the joining command from what a person typed.
fn joining_from(rest: &[String]) -> Result<daemon::control::Command, String> {
    // No name for the network. A person starting a join has not seen it and does
    // not know its suffix; the daemon writes under a name of its own and keeps the
    // network under one taken from the network itself once it arrives.
    let invite = rest
        .first()
        .filter(|word| !word.starts_with("--"))
        .cloned()
        .ok_or_else(|| format!("usage: {JOIN_USAGE}"))?;
    Ok(daemon::control::Command::Join { invite, name: device_name(rest)? })
}

/// Builds the inviting command from what a person typed.
fn inviting_from(rest: &[String]) -> Result<daemon::control::Command, String> {
    let name = rest
        .first()
        .filter(|word| !word.starts_with("--"))
        .cloned()
        .ok_or_else(|| format!("usage: {INVITE_USAGE}"))?;
    let groups = rest
        .windows(2)
        .filter(|pair| pair.first().is_some_and(|flag| flag == "--group"))
        .filter_map(|pair| pair.get(1).cloned())
        .collect();
    let minutes = match option(rest, "--expires") {
        None => None,
        Some(text) => Some(
            daemon::control::Command::expiry(&text)
                .map_err(|refusal| format!("{refusal}.\nusage: {INVITE_USAGE}"))?,
        ),
    };
    Ok(daemon::control::Command::Invite {
        network: option(rest, "--network"),
        name,
        admin: rest.iter().any(|word| word == "--admin"),
        light: rest.iter().any(|word| word == "--light"),
        groups,
        ipv4: option(rest, "--ipv4"),
        minutes,
    })
}

/// How long an invite still stays open, in words.
fn open_for(expires_at: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let minutes = expires_at.saturating_sub(now).div_ceil(60);
    let hours = minutes.div_ceil(60);
    if minutes <= 90 {
        format!("for up to {minutes} minutes")
    } else if hours <= 48 {
        format!("for up to {hours} hours")
    } else {
        format!("for up to {} days", hours.div_ceil(24))
    }
}

/// A moment, in seconds since the epoch, as the report draws one.
fn when(seconds: u64) -> String {
    std::time::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(seconds))
        .map_or_else(String::new, daemon::drawing::when)
}

/// Shows the key a relay's host answered with, and asks whether to sign it.
///
/// Founding and moving a relay ask with the same words, because they are asking
/// the same question: is this the relay you mean, or whatever answered first.
fn key_confirmed(relay: &str, key: &str) -> bool {
    println!();
    println!("  relay  {}", daemon::control::shown(relay));
    println!("  key    {key}");
    println!();
    println!("Nothing has checked that this is your relay. Anyone in the path could");
    println!("have answered. On the relay host, its container printed the same key when");
    println!("it started:");
    println!();
    println!("  docker logs <the relay container>");
    println!();
    print!("Sign this relay into the network? [yes/no] ");
    said_yes()
}

/// Reads a yes from the person standing here.
///
/// Anything that is not `yes` is a no. A confirmation that accepted `y`, `ok` or
/// an empty line would be one a person could give without having looked.
fn said_yes() -> bool {
    use std::io::Write as _;

    if std::io::stdout().flush().is_err() {
        return false;
    }
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    answer.trim().eq_ignore_ascii_case("yes")
}

/// Reads `--name value` from the words after the command.
fn option(rest: &[String], flag: &str) -> Option<String> {
    let at = rest.iter().position(|word| word == flag)?;
    rest.get(at.checked_add(1)?).cloned()
}

/// The options `found` takes, each followed by its value.
const FOUND_OPTIONS: [&str; 6] =
    ["--name", "--suffix", "--relay", "--ipv4-range", "--devices", "--window"];

/// How `found` is spelled, in one place so the usage and the refusal agree.
const FOUND_USAGE: &str = "peerfectly found <network> [--name N] [--suffix S] \
                           [--relay HOST | https://HOST:PORT | KEY@HOST:PORT] \
                           [--ipv4-range A.B.C.D/N | --devices N] [--window DAYS]";

/// What a freshness window buys, said when one is asked for.
const WINDOW_SENTENCE: &str = "with a window, a device that hears nothing signed by an admin for \
                               that long turns cautious: a cut-off island stops trusting a \
                               device revoked elsewhere, and stops working until it hears \
                               again. A network with an admin on every island wants none, \
                               which is the default.";

/// This device's name: the one a person gave, or one made from the machine's.
///
/// A name given is passed on as typed, for the daemon to check, which it does
/// for the phone as well; only that it will be kept in lower case is said here,
/// before anything is asked of a person. A name nobody gave is the machine's own,
/// because that is what a person will look for in a list, made into one a
/// resolver can answer, since there is nobody to ask about it.
///
/// # Errors
///
/// When no name is given and the machine's has nothing a name can use.
fn device_name(rest: &[String]) -> Result<String, String> {
    if let Some(given) = option(rest, "--name") {
        if let Ok(lowered) = daemon::usable(&given)
            && lowered != given
        {
            println!("this device is named `{lowered}`: a device's name is kept in lower case.");
        }
        return Ok(given);
    }
    named_after(machine_name().as_deref()).ok_or_else(|| {
        "this machine's name has nothing a device's name can use: give one with --name".to_owned()
    })
}

/// A device's name made from the machine's, when it has anything usable.
fn named_after(machine: Option<&str>) -> Option<String> {
    machine.and_then(daemon::made_usable)
}

/// The machine's own name, as the system has it.
fn machine_name() -> Option<String> {
    // Windows says it in `COMPUTERNAME`; elsewhere a shell may export
    // `HOSTNAME`, and the machine keeps it in `/etc/hostname`.
    ["COMPUTERNAME", "HOSTNAME"]
        .iter()
        .find_map(|variable| std::env::var(variable).ok())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
}

/// How `join` is spelled, in one place so the usage and the refusal agree.
const JOIN_USAGE: &str = "peerfectly join <the invite an admin sent> [--name NAME]";

/// How many devices of a batch file one command carries: well within what a
/// command may hold, at a few hundred bytes a device.
const BATCH_PART: usize = 100;

/// How `admit --batch` is spelled.
const ADMIT_USAGE: &str = "peerfectly admit --batch <file> [--network N] [--light] [--group G]... \
                           [--ipv6-only]";

/// What `admit --batch` was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AdmittingAsked {
    file: String,
    network: Option<String>,
    light: bool,
    groups: Vec<String>,
    ipv6_only: bool,
}

/// Reads the words after `admit`.
fn admitting_from(words: &[String]) -> Result<AdmittingAsked, String> {
    let usage = || format!("usage: {ADMIT_USAGE}");
    let mut asked = AdmittingAsked {
        file: String::new(),
        network: None,
        light: false,
        groups: Vec::new(),
        ipv6_only: false,
    };
    let mut rest = words.iter();
    while let Some(word) = rest.next() {
        match word.as_str() {
            "--batch" => asked.file = rest.next().ok_or_else(usage)?.clone(),
            "--network" => asked.network = Some(rest.next().ok_or_else(usage)?.clone()),
            "--light" => asked.light = true,
            "--group" => asked.groups.push(rest.next().ok_or_else(usage)?.clone()),
            "--ipv6-only" => asked.ipv6_only = true,
            _ => return Err(usage()),
        }
    }
    if asked.file.is_empty() {
        return Err(usage());
    }
    Ok(asked)
}

/// Everything waiting, as `peerfectly pending` shows it: the invites and the
/// requests they brought, this device's own joins, and an act stopped on a
/// person — each with what to do about it.
fn pending_listed(list: &daemon::control::PendingList) -> String {
    let mut out = String::new();
    if list.invites.is_empty() && list.joins.is_empty() && list.stopped.is_none() {
        return "nothing is waiting.\n".to_owned();
    }
    if let Some(stopped) = &list.stopped {
        out.push_str(&format!("waiting on you: {stopped}\n  to cancel it:  peerfectly cancel\n\n"));
    }
    for line in &list.invites {
        let name = daemon::control::shown(&line.name).to_string();
        let network = daemon::control::shown(&line.network).to_string();
        match (line.standing.as_str(), &line.request) {
            ("requested", Some(request)) => {
                out.push_str(&format!("{name} ({network}): a request waits for your approval\n"));
                out.push_str(&format!(
                    "  it asked to be called {}, arrived {}\n",
                    daemon::control::shown(&request.proposed_name),
                    when(request.arrived_at)
                ));
                out.push_str(&format!("  its key:  {}\n", request.fingerprint));
                if let Some(held) = &request.taken {
                    out.push_str(&format!(
                        "  {} is already held by {}: approve --replace revokes that device\n",
                        daemon::control::shown(&held.name),
                        held.id
                    ));
                }
                // What the device saw of the network's block against its own:
                // the network may want moving before it is approved.
                for conflict in &request.conflicts {
                    out.push_str(&format!("  its IPv4: {}\n", daemon::control::shown(conflict)));
                }
                out.push_str(&format!(
                    "  peerfectly approve {name}   ·   peerfectly reject {name}\n"
                ));
            }
            ("open", _) => out.push_str(&format!(
                "{name} ({network}): open {}, waiting for its device\n  peerfectly withdraw {name}\n",
                open_for(line.expires_at)
            )),
            ("approved", _) => out.push_str(&format!(
                "{name} ({network}): approved, and given the network as soon as it answers\n"
            )),
            (standing, _) => out.push_str(&format!("{name} ({network}): {standing}\n")),
        }
        out.push('\n');
    }
    for join in &list.joins {
        let label = daemon::control::shown(&join.label).to_string();
        let standing = match join.standing.as_str() {
            "registering" => "reaching the network's relay".to_owned(),
            "waiting" => "waiting for the admin's daemon to take the request".to_owned(),
            "requested" => format!(
                "the request was received{}; waiting for an admin to approve it",
                join.requested_at.map(|at| format!(" {}", when(at))).unwrap_or_default()
            ),
            "failed" => "it cannot go on".to_owned(),
            other => other.to_owned(),
        };
        out.push_str(&format!("this device's join `{label}`: {standing}\n"));
        if !join.fingerprint.is_empty() {
            out.push_str(&format!("  its key:  {}\n", join.fingerprint));
        }
        if let Some(problem) = &join.problem {
            out.push_str(&format!("  last: {problem}\n"));
        }
        out.push_str(&format!("  peerfectly cancel {label}\n\n"));
    }
    out
}

/// How `invite` is spelled, in one place so the usage and the refusal agree.
const INVITE_USAGE: &str = "peerfectly invite <name> [--network N] [--admin] [--light] \
                            [--group G]... [--ipv4 A.B.C.D] [--expires 30m|24h|7d]";

const REVOKE_USAGE: &str = daemon::control::Command::REVOKE_USAGE;

/// How `rename` is spelled, from the daemon's control module like `revoke`'s.
const RENAME_USAGE: &str = daemon::control::Command::RENAME_USAGE;

/// How `forget` is spelled, in one place so the usage and the refusal agree.
const FORGET_USAGE: &str = daemon::control::Command::FORGET_USAGE;

/// What a person can ask for.
///
/// Which lines need an administrator is the daemon's rule
/// ([`daemon::control::Command::word_needs_an_administrator`]), asked of each
/// line's word rather than written beside it, so the usage cannot say what the
/// daemon does not do.
fn usage(privileged: &str) -> String {
    use daemon::control::Command;

    let note = |line: &str| {
        let word = line.trim_start_matches("peerfectly ").split(' ').next().unwrap_or_default();
        if Command::word_needs_an_administrator(word) {
            format!("  (needs {privileged})")
        } else {
            String::new()
        }
    };

    let mut out = String::from("usage: peerfectly <command> [network]\n\ncommands:\n");
    for (word, takes_a_network) in Command::ALL {
        let network = if *takes_a_network { " [network]" } else { "" };
        out.push_str(&format!("  {word}{network}{}\n", note(word)));
    }
    // The words that take arguments are not among the single words `ALL`
    // holds, and are listed with their own spelling.
    out.push('\n');
    for line in [
        FOUND_USAGE,
        JOIN_USAGE,
        INVITE_USAGE,
        Command::APPROVE_USAGE,
        Command::REJECT_USAGE,
        Command::WITHDRAW_USAGE,
        "peerfectly cancel [join]",
        ADMIT_USAGE,
        REVOKE_USAGE,
        RENAME_USAGE,
        FORGET_USAGE,
        Command::RELAY_USAGE,
        Command::SET_ANCHORS_USAGE,
        Command::IPV4_USAGE,
        Command::ROUTE_USAGE,
        "peerfectly expose <network> tcp|udp <port>",
        "peerfectly unexpose <network> tcp|udp <port>",
        "peerfectly exposed [network]",
    ] {
        out.push_str(&format!("  {line}{}\n", note(line)));
    }
    out
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use daemon::control::Command;

    use super::named_after;

    /// A name nobody gave is the machine's, made into one a resolver answers.
    #[test]
    fn a_machine_name_is_made_into_a_device_name() {
        assert_eq!(named_after(Some("DESKTOP_RJUUBB3")).as_deref(), Some("desktop-rjuubb3"));
        assert_eq!(named_after(Some("Mario's PC")).as_deref(), Some("mario-s-pc"));
    }

    /// A machine whose name has nothing usable gives no name, and the command
    /// asks for `--name` rather than inventing one.
    #[test]
    fn a_machine_name_with_nothing_usable_gives_none() {
        assert_eq!(named_after(Some("___")), None);
        assert_eq!(named_after(None), None);
    }

    use super::founding_from;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    fn range_of(command: &Command) -> Option<String> {
        match command {
            Command::Found { ipv4_range, .. } => ipv4_range.clone(),
            other => panic!("expected a founding, got {other:?}"),
        }
    }

    #[test]
    fn found_takes_an_ipv4_range() {
        let command =
            founding_from(&words("casa --suffix casa.internal --ipv4-range 10.42.0.0/16")).unwrap();
        assert_eq!(range_of(&command).as_deref(), Some("10.42.0.0/16"));
    }

    #[test]
    fn found_without_the_flag_asks_for_the_default() {
        let command = founding_from(&words("casa")).unwrap();
        assert_eq!(range_of(&command), None);
    }

    #[test]
    fn found_takes_how_many_devices_or_a_block_and_not_both() {
        let command = founding_from(&words("casa --devices 500")).unwrap();
        assert!(matches!(command, Command::Found { devices: Some(500), ipv4_range: None, .. }));
        let both = founding_from(&words("casa --devices 500 --ipv4-range 10.42.0.0/16"));
        assert!(both.unwrap_err().contains("one or the other"));
        assert!(founding_from(&words("casa --devices none")).unwrap_err().contains("not a number"));
        assert!(super::FOUND_USAGE.contains("--devices"));
    }

    #[test]
    fn a_range_that_is_not_allowed_is_refused_before_the_daemon_is_asked() {
        let refusal = founding_from(&words("casa --ipv4-range 8.8.8.0/24")).unwrap_err();
        assert!(
            refusal.contains("8.8.8.0/24") && refusal.contains("Nothing was signed"),
            "{refusal}"
        );
    }

    #[test]
    fn the_usage_names_the_flag() {
        assert!(super::FOUND_USAGE.contains("--ipv4-range"));
        assert!(super::FOUND_USAGE.contains("--window"));
    }

    fn window_of(command: &Command) -> Option<u32> {
        match command {
            Command::Found { window_days, .. } => *window_days,
            other => panic!("expected a founding, got {other:?}"),
        }
    }

    #[test]
    fn a_default_founding_sets_no_window_and_one_is_taken_when_asked() {
        assert_eq!(window_of(&founding_from(&words("casa")).unwrap()), None);
        assert_eq!(window_of(&founding_from(&words("casa --window 7")).unwrap()), Some(7));
        assert!(
            founding_from(&words("casa --window 0")).is_err(),
            "zero is no window, said as none"
        );
    }

    /// The usage names the platform's own word for an administrator.
    #[test]
    fn the_usage_names_the_platforms_word_for_an_administrator() {
        assert!(
            super::usage("sudo")
                .contains("peerfectly expose <network> tcp|udp <port>  (needs sudo)")
        );
        assert!(!super::usage("sudo").contains("Administrator"), "the platform's own word, only");
    }

    /// The usage marks a word as needing an administrator exactly where the
    /// daemon's rule does: reading and turning a network on and off need none.
    #[test]
    fn the_usage_follows_the_daemons_rule() {
        let usage = super::usage("sudo");
        for free in [
            "  status
",
            "  up [network]
",
            "  down [network]
",
            "  pending [network]
",
        ] {
            assert!(usage.contains(free), "`{free}` needs nobody: {usage}");
        }
        assert!(
            usage.contains(
                "peerfectly exposed [network]
"
            ),
            "{usage}"
        );
        for acting in
            ["peerfectly approve", "peerfectly reject", "peerfectly forget", "peerfectly join"]
        {
            let line = usage.lines().find(|line| line.contains(acting)).expect("listed");
            assert!(line.ends_with("(needs sudo)"), "{line}");
        }
        assert!(usage.contains("--expires 30m|24h|7d"), "{usage}");
        assert!(!usage.contains("resume"), "there is nothing to come back to: {usage}");
    }

    /// The pending list says what waits and what to do about each: a request
    /// with its key and the device holding its name, and a join with its own.
    #[test]
    fn the_pending_list_says_what_to_do_about_each() {
        use daemon::control::{InviteLine, JoinLine, PendingList, RequestLine, TakenName};

        let list = PendingList {
            invites: vec![
                InviteLine {
                    network: "casa".to_owned(),
                    name: "laptop".to_owned(),
                    standing: "requested".to_owned(),
                    expires_at: 0,
                    request: Some(RequestLine {
                        proposed_name: "mario".to_owned(),
                        fingerprint: "AB12-CD34-EF56-7890-1234".to_owned(),
                        arrived_at: 1_800_000_000,
                        taken: Some(TakenName {
                            name: "laptop".to_owned(),
                            id: "0b0b-0b0b-0b0b-0b0b".to_owned(),
                        }),
                        conflicts: vec!["100.83.0.0/16 overlaps 100.83.4.0/24".to_owned()],
                    }),
                },
                InviteLine {
                    network: "casa".to_owned(),
                    name: "sensor".to_owned(),
                    standing: "used".to_owned(),
                    expires_at: 0,
                    request: None,
                },
            ],
            joins: vec![JoinLine {
                label: "joining".to_owned(),
                fingerprint: "9F00-1E2D-3C4B-5A69-7887".to_owned(),
                standing: "requested".to_owned(),
                since: 1_800_000_000,
                requested_at: Some(1_800_000_060),
                problem: None,
            }],
            stopped: None,
        };
        let shown = super::pending_listed(&list);
        assert!(shown.contains("AB12-CD34-EF56-7890-1234"), "{shown}");
        assert!(shown.contains("peerfectly approve laptop"), "{shown}");
        assert!(shown.contains("peerfectly reject laptop"), "{shown}");
        assert!(shown.contains("0b0b-0b0b-0b0b-0b0b"), "the device holding the name: {shown}");
        assert!(shown.contains("its IPv4: 100.83.0.0/16 overlaps"), "what the device saw: {shown}");
        assert!(shown.contains("sensor (casa): used"), "{shown}");
        assert!(shown.contains("9F00-1E2D-3C4B-5A69-7887"), "{shown}");
        assert!(shown.contains("peerfectly cancel joining"), "{shown}");
        assert_eq!(
            super::pending_listed(&PendingList::default()),
            "nothing is waiting.
"
        );
    }

    fn relay_of(command: &Command) -> Option<String> {
        match command {
            Command::Found { relay, .. } => relay.clone(),
            other => panic!("expected a founding, got {other:?}"),
        }
    }

    /// Each form of a relay reaches the daemon as typed; a host and a port with
    /// no key is refused here, naming the forms.
    #[test]
    fn a_relay_is_read_in_each_form_and_refused_without_one() {
        // A key a convesso relay really printed: every byte string is not a key.
        let written =
            "1c23b31d465a430ab24cc9e7990dd18ed67800950f7c3d035c3f6cb7747e5a89@relay.example:8443";
        for relay in [written, "relay.example", "https://relay.example:9443"] {
            let command = founding_from(&words(&format!("casa --relay {relay}"))).unwrap();
            assert_eq!(Some(relay.to_owned()), relay_of(&command));
        }
        let refusal = founding_from(&words("casa --relay relay.example:8443")).unwrap_err();
        assert!(refusal.contains("host of its peerfectly relay container"), "{refusal}");
        assert_eq!(None, relay_of(&founding_from(&words("casa")).unwrap()));
    }

    /// An option found does not take is refused, rather than ignored and found
    /// out later.
    #[test]
    fn an_option_found_does_not_take_is_refused() {
        for flags in ["--relays r.example", "--colour blue", "--now"] {
            let refusal =
                founding_from(&words(&format!("casa --relay relay.example {flags}"))).unwrap_err();
            assert!(refusal.contains("is not an option of found"), "{refusal}");
        }
        for option in super::FOUND_OPTIONS {
            assert!(super::FOUND_USAGE.contains(option), "{option} is in the usage");
        }
    }

    #[test]
    fn the_usage_shows_the_form_of_a_relay() {
        assert!(super::FOUND_USAGE.contains("KEY@HOST:PORT"));
        assert!(super::FOUND_USAGE.contains("--relay HOST"), "the host alone is enough");
        assert!(!super::JOIN_USAGE.contains("--relay"), "a join takes its relay from the invite");
    }

    /// An invite asks for what the device will be, and a join for the invite.
    #[test]
    fn invite_and_join_read_what_was_typed() {
        let Ok(Command::Invite { network, name, admin, light, groups, ipv4, minutes }) =
            super::inviting_from(&words(
                "sensor --network casa --light --group sensori --group cucina --ipv4 100.64.0.9 --expires 3h",
            ))
        else {
            panic!("an invite");
        };
        assert_eq!(network.as_deref(), Some("casa"));
        assert_eq!(name, "sensor");
        assert!(!admin && light);
        assert_eq!(groups, vec!["sensori".to_owned(), "cucina".to_owned()]);
        assert_eq!(ipv4.as_deref(), Some("100.64.0.9"));
        assert_eq!(minutes, Some(180));
        assert!(super::inviting_from(&words("--light")).is_err(), "a name first");
        assert!(super::inviting_from(&words("sensor --expires many")).is_err());

        let Ok(Command::Join { invite, name }) =
            super::joining_from(&words("peerfectly-invite-v1:00 --name board"))
        else {
            panic!("a join");
        };
        assert_eq!(invite, "peerfectly-invite-v1:00");
        assert_eq!(name, "board");
        assert!(super::joining_from(&words("--name board")).is_err(), "an invite first");
    }

    #[test]
    fn admitting_a_batch_reads_its_file_and_the_admin_s_choices() {
        let words = |line: &str| line.split(' ').map(str::to_owned).collect::<Vec<_>>();
        let asked = super::admitting_from(&words(
            "--batch lot.json --network casa --light --group sensori --group cucina --ipv6-only",
        ))
        .unwrap();
        assert_eq!(asked.file, "lot.json");
        assert_eq!(asked.network.as_deref(), Some("casa"));
        assert!(asked.light);
        assert_eq!(asked.groups, ["sensori", "cucina"]);
        assert!(asked.ipv6_only);
        assert!(super::admitting_from(&words("--light")).is_err(), "no file");
        assert!(super::admitting_from(&words("lot.json")).is_err(), "the file named by its flag");
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod custody {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use daemon::control::{Command, KeyWanted, Outcome, SignaturesWanted, SigningKind, ToSign};
    use roster::types::{OperationBody, OperationCore, Role};

    use super::{Asking, Channel, Cli, Extras, MadeKey, NoCustody, Unlocked};

    /// A daemon that answers from a script, and remembers what it was sent.
    struct Scripted {
        answers: Mutex<Vec<Outcome>>,
        sent: Mutex<Vec<Command>>,
    }

    impl Scripted {
        fn answering(answers: Vec<Outcome>) -> Self {
            Self { answers: Mutex::new(answers), sent: Mutex::new(Vec::new()) }
        }

        fn sent(&self) -> Vec<Command> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl Channel for Scripted {
        async fn ask(&self, command: Command) -> std::io::Result<Outcome> {
            self.sent.lock().unwrap().push(command);
            let mut answers = self.answers.lock().unwrap();
            Ok(if answers.is_empty() { Outcome::Done } else { answers.remove(0) })
        }
    }

    /// A custody that would sign anything, and counts how often it was asked —
    /// what stops a signature must be the command line, not a refusal here.
    #[derive(Default)]
    struct Willing {
        asked: AtomicUsize,
        /// Whether the key it makes comes back unlocked, as a passphrase just
        /// chosen does.
        unlocks: bool,
        /// Set when the unlocked key it handed out is dropped.
        dropped: std::sync::Arc<AtomicBool>,
        /// Set when the unlocked key it handed out signs.
        used: std::sync::Arc<AtomicUsize>,
    }

    struct JustMade {
        dropped: std::sync::Arc<AtomicBool>,
        used: std::sync::Arc<AtomicUsize>,
    }

    impl Unlocked for JustMade {
        fn sign_all(&self, messages: &[&[u8]]) -> Result<Vec<Vec<u8>>, String> {
            self.used.fetch_add(1, Ordering::SeqCst);
            Ok(messages.iter().map(|_| vec![8]).collect())
        }
    }

    impl Drop for JustMade {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl super::Custody for Willing {
        fn make_key(&self, _wanted: &KeyWanted) -> Result<MadeKey, String> {
            let unlocked: Option<Box<dyn Unlocked>> = self.unlocks.then(|| {
                Box::new(JustMade {
                    dropped: std::sync::Arc::clone(&self.dropped),
                    used: std::sync::Arc::clone(&self.used),
                }) as Box<dyn Unlocked>
            });
            Ok(MadeKey { public: vec![1], unlocked })
        }
        fn sign_all(&self, asking: &Asking<'_>) -> Result<Vec<Vec<u8>>, String> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            Ok(asking.messages.iter().map(|_| vec![9]).collect())
        }
    }

    /// An operation of the network these tests act on, as the daemon prepares it.
    fn core(body: OperationBody, parents: Vec<roster::id::OperationId>) -> OperationCore {
        let identity = identity::NodeIdentity::generate().unwrap();
        OperationCore::new(
            1_735_689_600_000,
            identity.signing_key().algorithm(),
            body,
            parents,
            identity.signing_key().key_id(),
            roster::id::NetworkId::from_bytes([0x42; 32]),
        )
        .unwrap()
    }

    fn operation(core: &OperationCore) -> ToSign {
        ToSign { kind: SigningKind::Operation, message: vec![1], payload: core.encode() }
    }

    fn snapshot_over(
        heads: Vec<roster::id::OperationId>,
        network: roster::id::NetworkId,
    ) -> ToSign {
        let identity = identity::NodeIdentity::generate().unwrap();
        let depths = vec![1; heads.len()];
        let body = roster::snapshot::Snapshot::new(
            1,
            Vec::new(),
            [0xa0; 32],
            roster::snapshot::Covering { heads, depths },
            Vec::new(),
            roster::leaf::DeviceLeaf {
                record: identity
                    .device_spec("pc", roster::types::Role::Admin, true, Vec::new())
                    .unwrap()
                    .into_record(roster::id::OperationId::from_bytes([1; 32]))
                    .unwrap(),
                settings: roster::leaf::DeviceSettings::default(),
            },
            roster::membership::MembershipProof {
                devices: roster::merkle::Proof { siblings: Vec::new() },
                parameters: [0; 32],
            },
            identity.signing_key().key_id(),
            network,
        )
        .unwrap();
        ToSign { kind: SigningKind::Snapshot, message: vec![2], payload: body.encode() }
    }

    fn wanted(key: &str, items: Vec<ToSign>) -> Outcome {
        Outcome::NeedsSignatures(SignaturesWanted {
            id: "b1".to_owned(),
            key: key.to_owned(),
            network: "casa".to_owned(),
            items,
        })
    }

    fn signed(sent: &[Command]) -> Option<Vec<Vec<u8>>> {
        sent.iter().find_map(|command| match command {
            Command::Signed { signatures, .. } => Some(signatures.clone()),
            _ => None,
        })
    }

    /// **A refusal for want of authority is a failure, and says so**: not a
    /// silent success.
    #[test]
    fn a_refusal_is_not_a_success() {
        let daemon = Scripted::answering(Vec::new());
        let cli = Cli { channel: &daemon, custody: &NoCustody, extras: Extras::default() };
        let refused = Outcome::NotAllowed {
            message: "not authorised: stopping is an administrator's".to_owned(),
        };
        assert_eq!(std::process::ExitCode::FAILURE, cli.shown(&Command::Stop, Ok(refused)));
        assert_eq!(std::process::ExitCode::SUCCESS, cli.shown(&Command::Stop, Ok(Outcome::Done)));
    }

    /// **A join waiting for its proof of possession gets it**, from custody,
    /// and carries on: the wait asks through the wrapper that signs.
    #[tokio::test]
    async fn a_join_that_needs_its_proof_is_signed_and_goes_on() {
        let daemon = Scripted::answering(vec![
            Outcome::NeedsSignatures(SignaturesWanted {
                id: "p1".to_owned(),
                key: "peerfectly.network.0123456789abcdef.signing".to_owned(),
                network: "casa".to_owned(),
                items: vec![ToSign {
                    kind: SigningKind::Possession,
                    message: vec![7; 32],
                    payload: Vec::new(),
                }],
            }),
            Outcome::Failed { message: "stop here".to_owned(), left_behind: Vec::new() },
        ]);
        let custody = Willing::default();
        let cli = Cli { channel: &daemon, custody: &custody, extras: Extras::default() };
        let joining = Command::Join { invite: "an invite".to_owned(), name: "laptop".to_owned() };
        assert_eq!(std::process::ExitCode::FAILURE, cli.join(joining).await);
        let sent = daemon.sent();
        assert!(
            sent.iter().any(|command| matches!(command, Command::Signed { id, .. } if id == "p1")),
            "the proof was signed and sent: {sent:?}"
        );
    }

    /// **Without custody, a signature asked for is refused in words, and the
    /// daemon is told**, as it is when a person declines.
    #[tokio::test]
    async fn a_signature_is_refused_and_the_daemon_is_told() {
        let daemon = Scripted::answering(vec![Outcome::NeedsSignatures(SignaturesWanted {
            id: "7".to_owned(),
            key: "a key".to_owned(),
            network: "casa".to_owned(),
            items: vec![ToSign {
                kind: SigningKind::Possession,
                message: vec![1, 2, 3],
                payload: Vec::new(),
            }],
        })]);
        let cli = Cli { channel: &daemon, custody: &NoCustody, extras: Extras::default() };

        let outcome = cli.ask_and_sign(Command::Status).await.unwrap();

        let Outcome::Declined { message } = outcome else { panic!("{outcome:?}") };
        assert!(message.contains("cannot protect a signing key"), "{message}");
        let sent = daemon.sent();
        assert!(sent.contains(&Command::NotSigned { id: "7".to_owned() }), "{sent:?}");
        assert!(signed(&sent).is_none(), "{sent:?}");
    }

    /// **An act other than the one asked for is never signed**, however willing
    /// the key: a person who typed `revoke laptop` and is handed a promotion has
    /// been handed somebody else's act.
    #[tokio::test]
    async fn another_act_is_not_signed_whatever_custody_would_do() {
        let promotion = core(
            OperationBody::Promote {
                device: roster::id::DeviceId::from_bytes([0x11; 32]),
                founder: false,
            },
            Vec::new(),
        );
        let daemon = Scripted::answering(vec![wanted("a key", vec![operation(&promotion)])]);
        let custody = Willing::default();
        let cli = Cli { channel: &daemon, custody: &custody, extras: Extras::default() };
        let revoking = Command::Revoke {
            network: None,
            target: daemon::control::Target::Name("laptop".to_owned()),
            reason: "sold".to_owned(),
        };

        let outcome = cli.ask_and_sign(revoking).await.unwrap();

        assert!(matches!(outcome, Outcome::Failed { .. }), "{outcome:?}");
        let sent = daemon.sent();
        assert!(sent.contains(&Command::NotSigned { id: "b1".to_owned() }), "{sent:?}");
        assert!(signed(&sent).is_none(), "{sent:?}");
        assert_eq!(0, custody.asked.load(Ordering::SeqCst), "and nobody was asked");
    }

    /// **A batch that does not hold together is refused whole**, before anyone
    /// is asked: here a snapshot that covers nothing the batch does.
    #[tokio::test]
    async fn a_batch_that_does_not_hold_together_is_not_signed() {
        let revocation = core(
            OperationBody::RevokeDevice {
                device: roster::id::DeviceId::from_bytes([0x11; 32]),
                reason: "sold".to_owned(),
            },
            Vec::new(),
        );
        let stray = snapshot_over(
            vec![roster::id::OperationId::from_bytes([5; 32])],
            roster::id::NetworkId::from_bytes([0x42; 32]),
        );
        let daemon =
            Scripted::answering(vec![wanted("a key", vec![operation(&revocation), stray])]);
        let custody = Willing::default();
        let cli = Cli { channel: &daemon, custody: &custody, extras: Extras::default() };
        let revoking = Command::Revoke {
            network: None,
            target: daemon::control::Target::Name("laptop".to_owned()),
            reason: "sold".to_owned(),
        };

        let outcome = cli.ask_and_sign(revoking).await.unwrap();

        let Outcome::Failed { message, .. } = outcome else { panic!("{outcome:?}") };
        assert!(message.contains("does not cover"), "{message}");
        let sent = daemon.sent();
        assert!(sent.contains(&Command::NotSigned { id: "b1".to_owned() }), "{sent:?}");
        assert_eq!(0, custody.asked.load(Ordering::SeqCst), "nobody was asked");
    }

    /// **A replacement is shown whole and signed at once**: three acts, one
    /// asking, three signatures back in order.
    #[tokio::test]
    async fn a_replacement_is_asked_for_once() {
        let revocation = core(
            OperationBody::RevokeDevice {
                device: roster::id::DeviceId::from_bytes([0x11; 32]),
                reason: "replaced by a device admitted under the name `laptop`".to_owned(),
            },
            Vec::new(),
        );
        let joiner = identity::NodeIdentity::generate().unwrap();
        let admission = core(
            OperationBody::AddDevice(
                joiner.device_spec("laptop", Role::Member, false, Vec::new()).unwrap(),
            ),
            vec![revocation.id()],
        );
        let snapshot = snapshot_over(vec![admission.id()], revocation.network);
        let daemon = Scripted::answering(vec![
            wanted("a key", vec![operation(&revocation), operation(&admission), snapshot]),
            Outcome::Done,
        ]);
        let custody = Willing::default();
        let cli = Cli { channel: &daemon, custody: &custody, extras: Extras::default() };

        let approving =
            Command::Approve { network: None, name: "laptop".to_owned(), replace: true };
        let outcome = cli.ask_and_sign(approving).await.unwrap();

        assert_eq!(Outcome::Done, outcome);
        assert_eq!(1, custody.asked.load(Ordering::SeqCst), "one asking for the whole act");
        assert_eq!(Some(vec![vec![9], vec![9], vec![9]]), signed(&daemon.sent()));
    }

    /// **Founding asks only to choose the passphrase.** The key is made, comes
    /// back unlocked, and the very next answer is the batch it signs: signed with
    /// it, nobody asked a third time — and then dropped.
    #[tokio::test]
    async fn a_key_just_made_signs_its_founding_without_asking_again() {
        let identity = identity::NodeIdentity::generate().unwrap();
        let founder = identity.device_spec("desktop", Role::Admin, true, Vec::new()).unwrap();
        let params = roster::types::NetworkParams::new(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            "home.internal",
            2_592_000,
        )
        .unwrap();
        let genesis = OperationCore::new(
            1,
            identity.signing_key().algorithm(),
            OperationBody::CreateNetwork { device: founder, params },
            Vec::new(),
            identity.signing_key().key_id(),
            roster::id::NetworkId::from_bytes([0; 32]),
        )
        .unwrap();
        let network = roster::id::NetworkId::from_bytes(*genesis.id().as_bytes());
        let snapshot = snapshot_over(vec![genesis.id()], network);

        let daemon = Scripted::answering(vec![
            Outcome::NeedsKey(KeyWanted {
                id: "k1".to_owned(),
                name: "peerfectly.casa.signing".to_owned(),
                network: "casa".to_owned(),
            }),
            wanted("peerfectly.casa.signing", vec![operation(&genesis), snapshot]),
            Outcome::Done,
        ]);
        let custody = Willing { unlocks: true, ..Willing::default() };
        let cli = Cli { channel: &daemon, custody: &custody, extras: Extras::default() };
        let founding = Command::Found {
            label: "casa".to_owned(),
            name: "desktop".to_owned(),
            suffix: "home.internal".to_owned(),
            relay: None,
            ipv4_range: None,
            devices: None,
            window_days: None,
        };

        let outcome = cli.ask_and_sign(founding).await.unwrap();

        assert_eq!(Outcome::Done, outcome);
        assert_eq!(0, custody.asked.load(Ordering::SeqCst), "nobody was asked again");
        assert_eq!(1, custody.used.load(Ordering::SeqCst), "the key just made signed");
        assert_eq!(Some(vec![vec![8], vec![8]]), signed(&daemon.sent()));
        assert!(custody.dropped.load(Ordering::SeqCst), "and it is gone");
    }

    /// **Cancelling with one join waiting cancels that join**, by the name the
    /// list gives it; with an act stopped on a person, that act.
    #[tokio::test]
    async fn cancel_finds_what_waits() {
        use daemon::control::{JoinLine, PendingList};

        let join = JoinLine {
            label: "joining".to_owned(),
            fingerprint: String::new(),
            standing: "waiting".to_owned(),
            since: 0,
            requested_at: None,
            problem: None,
        };
        let daemon = Scripted::answering(vec![
            Outcome::Pending(PendingList { joins: vec![join], ..PendingList::default() }),
            Outcome::Done,
        ]);
        let custody = Willing::default();
        let cli = Cli { channel: &daemon, custody: &custody, extras: Extras::default() };
        assert_eq!(std::process::ExitCode::SUCCESS, cli.cancel_waiting(None).await);
        assert_eq!(
            daemon.sent().last(),
            Some(&Command::CancelJoin { label: "joining".to_owned() })
        );

        let daemon = Scripted::answering(vec![
            Outcome::Pending(PendingList {
                stopped: Some("the founding of `casa`".to_owned()),
                ..PendingList::default()
            }),
            Outcome::Done,
        ]);
        let cli = Cli { channel: &daemon, custody: &custody, extras: Extras::default() };
        assert_eq!(std::process::ExitCode::SUCCESS, cli.cancel_waiting(None).await);
        assert_eq!(daemon.sent().last(), Some(&Command::Abandon));
    }

    /// **A key made before a pause is not kept across it.** A join makes its key
    /// and then waits for the admin; the unlocked key is dropped at that answer,
    /// and nothing signs with it.
    #[tokio::test]
    async fn a_key_just_made_is_dropped_when_the_answer_is_not_its_batch() {
        let daemon = Scripted::answering(vec![
            Outcome::NeedsKey(KeyWanted {
                id: "k1".to_owned(),
                name: "peerfectly.casa.signing".to_owned(),
                network: "casa".to_owned(),
            }),
            Outcome::JoinStarted {
                label: "joining".to_owned(),
                fingerprint: "AB12-CD34-EF56-7890-1234".to_owned(),
                conflicts: Vec::new(),
            },
        ]);
        let custody = Willing { unlocks: true, ..Willing::default() };
        let cli = Cli { channel: &daemon, custody: &custody, extras: Extras::default() };

        let joining = Command::Join { invite: "an invite".to_owned(), name: "laptop".to_owned() };
        let outcome = cli.ask_and_sign(joining).await.unwrap();

        assert_eq!(
            Outcome::JoinStarted {
                label: "joining".to_owned(),
                fingerprint: "AB12-CD34-EF56-7890-1234".to_owned(),
                conflicts: Vec::new(),
            },
            outcome
        );
        assert!(custody.dropped.load(Ordering::SeqCst), "dropped at the first other answer");
        assert_eq!(0, custody.used.load(Ordering::SeqCst), "and never used");
    }

    /// **A batch for another key is not signed with the one just made**: it is
    /// dropped, and the platform asks as usual.
    #[tokio::test]
    async fn a_key_just_made_signs_only_its_own_batch() {
        let revocation = core(
            OperationBody::RevokeDevice {
                device: roster::id::DeviceId::from_bytes([0x11; 32]),
                reason: "sold".to_owned(),
            },
            Vec::new(),
        );
        let daemon = Scripted::answering(vec![
            Outcome::NeedsKey(KeyWanted {
                id: "k1".to_owned(),
                name: "peerfectly.casa.signing".to_owned(),
                network: "casa".to_owned(),
            }),
            wanted("peerfectly.other.signing", vec![operation(&revocation)]),
            Outcome::Done,
        ]);
        let custody = Willing { unlocks: true, ..Willing::default() };
        let cli = Cli { channel: &daemon, custody: &custody, extras: Extras::default() };

        let outcome = cli.ask_and_sign(Command::Confirm).await.unwrap();

        assert_eq!(Outcome::Done, outcome);
        assert_eq!(0, custody.used.load(Ordering::SeqCst), "not with the key just made");
        assert_eq!(1, custody.asked.load(Ordering::SeqCst), "the platform asked");
    }

    /// **The only admin is asked, and yes sends the removal again with the
    /// acknowledgement.**
    #[tokio::test]
    async fn the_only_admin_is_asked_and_yes_resends() {
        let daemon = Scripted::answering(vec![Outcome::Done]);
        let cli = Cli { channel: &daemon, custody: &NoCustody, extras: Extras::default() };

        let answer = cli
            .when_only_admin(Ok(Outcome::OnlyAdmin { network: "casa".to_owned() }), || true)
            .await
            .unwrap();

        assert_eq!(Outcome::Done, answer);
        assert_eq!(
            vec![Command::Forget { label: "casa".to_owned(), last_admin: true }],
            daemon.sent()
        );
    }

    /// **No sends nothing more**, and is not a success.
    #[tokio::test]
    async fn the_only_admin_saying_no_removes_nothing() {
        let daemon = Scripted::answering(Vec::new());
        let cli = Cli { channel: &daemon, custody: &NoCustody, extras: Extras::default() };

        let answer = cli
            .when_only_admin(Ok(Outcome::OnlyAdmin { network: "casa".to_owned() }), || false)
            .await;

        assert!(daemon.sent().is_empty(), "nothing was sent");
        let forget = Command::Forget { label: "casa".to_owned(), last_admin: false };
        assert_eq!(std::process::ExitCode::FAILURE, cli.shown(&forget, answer));
    }

    /// **Without custody, no key is made**, and the daemon is told nothing was.
    #[tokio::test]
    async fn a_key_is_refused_and_none_is_made() {
        let daemon = Scripted::answering(vec![Outcome::NeedsKey(KeyWanted {
            id: "8".to_owned(),
            name: "peerfectly.casa.signing".to_owned(),
            network: "casa".to_owned(),
        })]);
        let cli = Cli { channel: &daemon, custody: &NoCustody, extras: Extras::default() };

        let outcome = cli.ask_and_sign(Command::Status).await.unwrap();

        let Outcome::Failed { message, .. } = outcome else { panic!("{outcome:?}") };
        assert!(message.contains("cannot protect a signing key"), "{message}");
        let sent = daemon.sent();
        assert!(!sent.iter().any(|one| matches!(one, Command::KeyMade { .. })), "{sent:?}");
    }
}

#[cfg(test)]
mod portable {
    /// **The portable command line names no platform.** What a platform gives
    /// it arrives through `Channel` and `Custody`; a Windows import here would be
    /// a second Windows command line waiting to happen.
    #[test]
    fn it_names_no_platform() {
        let source = include_str!("lib.rs");
        let code: String = source
            .split("#[cfg(test)]")
            .next()
            .unwrap_or(source)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for platform in ["cfg(windows)", "windows_sys", "windows_daemon", "platform::", "target_os"]
        {
            assert!(!code.contains(platform), "`{platform}` in the portable command line");
        }
    }
}

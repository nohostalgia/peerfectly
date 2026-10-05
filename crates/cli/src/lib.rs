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
}

impl Default for Extras {
    fn default() -> Self {
        Self { usage: "", privileged: "Administrator", after_status: || {} }
    }
}

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
        self.channel.ask(command).await
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
            return runtime.block_on(self.enrol_through_the_daemon(command));
        }

        // Admitting goes through the daemon, because the daemon holds the roster: an
        // operation appended by another process would be invisible to it until it
        // restarted, and a device admitted into a roster nobody is using cannot
        // connect.
        if word == "admit" {
            let Some(payload) = std::env::args().nth(2) else {
                eprintln!("usage: {ADMIT_USAGE}");
                return ExitCode::FAILURE;
            };
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(cause) => {
                    eprintln!("could not start: {cause}");
                    return ExitCode::FAILURE;
                }
            };
            return runtime.block_on(self.admit_through_the_daemon(payload));
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

        // Setting a network's rendezvous: a signed parameter change, like the relay's.
        if word == "rendezvous" {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            let command = match daemon::control::Command::rendezvous_change(&rest) {
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
            return runtime.block_on(self.change_rendezvous(command));
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
            self.shown(&asked, answer)
        })
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
                    Command::Peers { network } => {
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
            Ok(Outcome::Done) => ExitCode::SUCCESS,
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

    /// Sets or removes a network's rendezvous, signing as the network's admin.
    async fn change_rendezvous(&self, command: daemon::control::Command) -> std::process::ExitCode {
        use std::process::ExitCode;

        use daemon::control::Outcome;

        match self.ask_and_sign(command).await {
            Ok(Outcome::Reported(report)) => {
                print!("{report}");
                println!();
                println!("the rendezvous was changed. The other devices follow once they hold it.");
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
    /// from the certificate: it loses every device switched off right now, and a
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
            Ok(Outcome::Pinning { relay, fingerprint, der_len, .. }) => {
                if !pin_confirmed(&relay, &fingerprint, der_len) {
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
                println!("  on the device joining:  peerfectly join --relay <the relay>");
                println!("  back here:              peerfectly admit <what it printed>");
                ExitCode::SUCCESS
            }

            // A certificate nobody has vouched for, waiting on a person.
            Outcome::Pinning { relay, fingerprint, der_len, .. } => {
                if !pin_confirmed(&relay, &fingerprint, der_len) {
                    let _ = self.ask(Command::Abandon).await;
                    println!("nothing was signed.");
                    return ExitCode::FAILURE;
                }
                self.finish(&expected).await
            }

            // A join. The daemon answers before it has reached the relay, so the
            // payload is asked for rather than returned: it is the same asking the
            // code needs later, and it keeps the daemon free to answer other
            // commands while a relay takes its time.
            Outcome::Joining { .. } => {
                println!("registering at the relay...");
                self.wait_for_the_code().await
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

    /// Asks the daemon what the join has got to, until a code appears.
    async fn wait_for_the_code(&self) -> std::process::ExitCode {
        use std::process::ExitCode;

        use daemon::control::{Command, Outcome};

        let mut shown = false;
        loop {
            // Ctrl+C ends the wait for the daemon too. Without this the command line
            // died and the daemon kept the enrolment endpoint registered at the relay
            // until its wait ran out — an endpoint outliving the request that opened it.
            tokio::select! {
                () = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
                _ = tokio::signal::ctrl_c() => {
                    let _ = self.ask(Command::Abandon).await;
                    println!();
                    println!("abandoned; nothing was written.");
                    return ExitCode::FAILURE;
                }
            }
            // Through the wrapper: the join may stop here for this device to
            // prove it holds its own signing key, and where that key is held
            // elsewhere the proof is made here, as every other signature is.
            // Asked plainly, the request came back as an answer this loop did
            // not know, and a join from the command line could not finish.
            match self.ask_and_sign(Command::Waiting).await {
                Ok(Outcome::Joining { payload, scannable }) => {
                    if !shown && !payload.is_empty() {
                        shown = true;
                        println!();
                        println!("{scannable}");
                        println!(
                            "waiting to be admitted. On the machine that admits this one, run:"
                        );
                        println!();
                        println!("  peerfectly admit {payload}");
                        println!();
                        println!("or scan the code above.");
                    }
                }
                Ok(Outcome::Enrolling) => {
                    println!();
                    println!("An admin has reached this device, and is showing six digits.");
                    println!();
                    println!("Read them off that machine — not this one, which shows none — and");
                    println!("type them here. If the machine you are standing at shows nothing,");
                    println!("or shows something else, stop: whoever answered is not the admin");
                    println!("you meant, and nothing has been signed.");
                    println!();
                    print!("The six digits it shows: ");
                    let Some(typed) = read_a_line() else {
                        let _ = self.ask(Command::Abandon).await;
                        println!("abandoned; nothing was written.");
                        return ExitCode::FAILURE;
                    };
                    return self.finish_join(typed).await;
                }
                Ok(Outcome::Declined { message }) | Ok(Outcome::Failed { message, .. }) => {
                    eprintln!("{message}");
                    return ExitCode::FAILURE;
                }
                // The daemon holds nothing any more: somebody abandoned this wait
                // from somewhere else. Said as what it is, rather than as an answer
                // this command did not expect.
                Ok(Outcome::Done) => {
                    eprintln!("the wait was abandoned; nothing was written.");
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
    }

    /// Finishes a join with the digits a person read off the admitting machine.
    ///
    /// Separate from [`finish`] because it carries something: a join is confirmed by
    /// what a person typed, and never by this side agreeing with itself.
    async fn finish_join(&self, code: String) -> std::process::ExitCode {
        use std::process::ExitCode;

        use daemon::control::{Command, Outcome};

        match self.ask_and_sign(Command::ConfirmJoin { code }).await {
            Ok(Outcome::Adopted { suffix, devices, relay_confirmed, carrying }) => {
                println!();
                println!("joined. this device is a member of a network with {devices} devices.");
                if !relay_confirmed {
                    println!();
                    println!("note: that relay was accepted on sight and the network pins no");
                    println!("      certificate, so nothing has ever vouched for it.");
                }
                println!();
                // What is offered is what is left to do. A join that replaced this
                // device's membership in a network that was up comes back up, so
                // telling a person to raise it would be telling them to do what has
                // already been done — and would leave them doubting what they see.
                if carrying {
                    println!("this network is carrying traffic.");
                    println!();
                    println!("next:");
                } else {
                    println!("next:");
                    println!("  bring the tunnel up:  peerfectly up");
                }
                println!("  names resolve under:  .{suffix}");
                ExitCode::SUCCESS
            }
            Ok(Outcome::Declined { message }) | Ok(Outcome::Failed { message, .. }) => {
                eprintln!("{message}");
                // A code that did not match leaves nothing waiting: the exchange is
                // over on both machines, and starting again is a new one.
                let _ = self.ask(Command::Abandon).await;
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
            Ok(Outcome::Adopted { suffix, devices, relay_confirmed, carrying }) => {
                println!();
                println!("joined. this device is a member of a network with {devices} devices.");
                if !relay_confirmed {
                    println!();
                    println!("note: that relay was accepted on sight and the network pins no");
                    println!("      certificate, so nothing has ever vouched for it.");
                }
                println!();
                // What is offered is what is left to do. A join that replaced this
                // device's membership in a network that was up comes back up, so
                // telling a person to raise it would be telling them to do what has
                // already been done — and would leave them doubting what they see.
                if carrying {
                    println!("this network is carrying traffic.");
                    println!();
                    println!("next:");
                } else {
                    println!("next:");
                    println!("  bring the tunnel up:  peerfectly up");
                }
                println!("  names resolve under:  .{suffix}");
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

    /// Admits a device, with a person comparing two screens in the middle.
    async fn admit_through_the_daemon(&self, payload: String) -> std::process::ExitCode {
        use std::io::Write as _;
        use std::process::ExitCode;

        use daemon::control::{Command, Outcome};

        let opened = match self.ask(Command::Admit { network: network_option(), payload }).await {
            Ok(outcome) => outcome,
            Err(cause) => {
                eprintln!("{cause}");
                return ExitCode::FAILURE;
            }
        };

        let Outcome::Admitting { proposed_name, fingerprint, code, taken, .. } = opened else {
            return match opened {
                Outcome::Declined { message } | Outcome::Failed { message, .. } => {
                    eprintln!("{message}");
                    ExitCode::FAILURE
                }
                _ => {
                    eprintln!("the daemon answered something unexpected");
                    ExitCode::FAILURE
                }
            };
        };

        println!();
        println!("  device asking to join:  {proposed_name}");
        println!("  its signing key:        {fingerprint}");
        println!();
        println!("      {code}");
        println!();
        // Naming the screen is the whole point. A prompt that asked about a number
        // on this screen would defend nothing against a payload substituted on its
        // way here — the person has to look at the other machine.
        println!("Now go to the device you are enrolling and type those six digits into it.");
        println!("Nothing has been signed, and nothing will be until it says they matched.");
        println!();
        print!("waiting for that device");
        let _ = std::io::Write::flush(&mut std::io::stdout());

        // Waited for here rather than asked about first: until that device has
        // accepted, there is nothing for a person to look at, and a question about a
        // screen that has not changed yet is one they answer wrongly.
        if !self.wait_until_accepted().await {
            println!();
            let _ = self.ask(Command::Abandon).await;
            eprintln!("that device did not say the code was accepted. Nothing was signed, and");
            eprintln!("neither machine has changed. Start again when you are at both of them.");
            return ExitCode::FAILURE;
        }

        println!();
        println!();
        println!("That device says the code was accepted.");
        println!();
        println!("Look at it: it must be the machine you meant to enrol, and it must be the one");
        println!("saying so. If what said yes is not the machine in front of you, say no.");
        println!();
        print!("Sign the admission? [yes/no] ");
        let _ = std::io::stdout().flush();

        let mut answer = String::new();
        let agreed = std::io::stdin().read_line(&mut answer).is_ok()
            && matches!(answer.trim().to_ascii_lowercase().as_str(), "yes" | "y");

        if !agreed {
            let _ = self.ask(Command::Abandon).await;
            eprintln!("nothing was signed, and neither machine has changed.");
            return ExitCode::FAILURE;
        }

        // A name this network already uses. Before this the second device quietly
        // became `name-2` and the admin found out from the device list.
        let confirmation = match &taken {
            None => Command::Confirm,
            Some(held) => {
                println!();
                println!(
                    "This network already has a device called {}.",
                    daemon::control::shown(&held.name)
                );
                println!();
                println!("  it is  {}  {}", held.id, daemon::control::shown(&held.name));
                println!();
                println!(
                    "That is not this device. The one asking to join has its own keys and will"
                );
                println!(
                    "have its own identifier whatever it is called, so this is a question about"
                );
                println!("a name and not about a machine.");
                println!();
                println!("Replacing revokes {} and gives the name to the device", held.id);
                println!(
                    "joining now. A revocation cannot be undone: that device never returns to"
                );
                println!("this network, whoever holds it.");
                println!();
                print!("Replace it? [yes/no, no admits under another name] ");
                let _ = std::io::stdout().flush();
                let mut said = String::new();
                let replacing = std::io::stdin().read_line(&mut said).is_ok()
                    && matches!(said.trim().to_ascii_lowercase().as_str(), "yes" | "y");
                if replacing { Command::Replace } else { Command::Confirm }
            }
        };

        match self.ask_and_sign(confirmation).await {
            Ok(Outcome::Reported(report)) => {
                print!("{report}");
                ExitCode::SUCCESS
            }
            Ok(Outcome::Declined { message }) | Ok(Outcome::Failed { message, .. }) => {
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

    /// Waits until the device being enrolled says the code matched.
    ///
    /// Polls the daemon, which is listening on the exchange. `false` when the
    /// exchange ends without it — a deadline, a device that said something else, or
    /// a person who walked away.
    async fn wait_until_accepted(&self) -> bool {
        use daemon::control::{Command, Outcome};

        // The exchange's own deadline is what bounds this; the count is generous
        // enough to cover it and no more.
        for _ in 0..240_u32 {
            tokio::select! {
                () = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
                _ = tokio::signal::ctrl_c() => return false,
            }
            match self.ask(Command::Waiting).await {
                Ok(Outcome::Admitting { accepted: true, .. }) => return true,
                Ok(Outcome::Admitting { accepted: false, .. }) => {
                    print!(".");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
                _ => return false,
            }
        }
        false
    }
}

/// Builds the founding command from what a person typed.
///
/// The parsing stays here — it is what a terminal is for — and the work goes to
/// the daemon. A certificate read from a file is read here, because the path is
/// the person's; one fetched from a relay is fetched there, because that is the
/// process that will use it and because doing it here would mean two processes
/// talking to the relay about the same thing.
fn founding_from(rest: &[String]) -> Result<daemon::control::Command, String> {
    use daemon::control::{Certificate, Command};
    use daemon::relay;

    // The network's name, which is this machine's own name for it. The device's
    // own name is separate and has a sensible default; the network's does not,
    // because it is the word a person will type at every later command.
    let label = rest
        .first()
        .filter(|word| !word.starts_with("--"))
        .ok_or_else(|| format!("usage: {FOUND_USAGE}"))?
        .clone();
    let name = option(rest, "--name").unwrap_or_else(default_name);

    let relay_address = option(rest, "--relay");

    // The relay's certificate is fetched **by default** where there is a relay to
    // fetch it from.
    //
    // # Why this is not a flag a person has to know about
    //
    // An admitting side pins the relay's certificate only where the network does:
    // `transport-iroh`'s enrolment endpoint adds `ca_tls_config` under `if let
    // Some(certificate) = state.params.relay_cert`, and otherwise verifies against
    // the system's roots. So a network founded against a relay whose certificate
    // no public authority vouches for — a self-signed one on a bare address is the
    // ordinary case — and **not** pinned can never admit anybody: the admitting
    // side cannot reach the relay at all.
    //
    // The joining side has no such trouble. It accepts on sight when ordinary
    // verification fails, registers, and shows its payload exactly as it should,
    // then waits out its ten minutes. So the failure appears on the machine that
    // is working, and nothing anywhere mentions a certificate. That cost an
    // evening of two-machine testing; it is written down in `VERIFICATION.md` §29.
    //
    // Nothing about the pause changes. The fingerprint is still shown and still
    // confirmed before anything is signed — what changes is which way round the
    // question is put, and which answer a person gets by not thinking about it.
    let declining = rest.iter().any(|word| word == "--no-relay-cert");
    let given = option(rest, "--relay-cert");
    if given.is_some() && declining {
        return Err("--relay-cert and --no-relay-cert disagree; use one or the other".to_owned());
    }
    let certificate = match given {
        Some(path) => {
            let certificate = relay::read_certificate(&path)?;
            // A file may legitimately be a certificate authority's certificate
            // that signs the one the relay presents, and this cannot tell the two
            // apart — so this is said and not enforced. The fetch, which knows it
            // holds the relay's own certificate, does enforce it.
            if let Some(address) = relay_address.as_deref() {
                let (host, _) = relay::host_and_port(address)?;
                if let Err(reason) = relay::usable_as_a_server_certificate(&certificate, &host) {
                    println!("warning: {address} cannot present this certificate itself:");
                    println!("{reason}");
                    println!(
                        "pinning it anyway — right only if it signs the one the relay serves."
                    );
                    println!();
                }
            }
            Certificate::Given(certificate)
        }
        // A relay and no objection: fetch it, show the fingerprint, and pin it
        // only once a person says it matches.
        None if !declining && relay_address.is_some() => Certificate::FromTheRelay,
        // No relay to fetch from, or a person who said not to — and who is
        // told what that costs before the founding is signed.
        None => {
            if declining && relay_address.is_some() {
                println!();
                println!("Founding without pinning that relay's certificate.");
                println!();
                println!("If it presents one no public authority vouches for, this network will");
                println!("never be able to admit another device: admitting verifies against the");
                println!("system's roots when the network pins nothing, and cannot reach the");
                println!("relay at all. The device trying to join will wait and time out, and");
                println!("nothing will mention a certificate.");
                println!();
            }
            Certificate::None
        }
    };

    // Read here as well as in the daemon, so a range that is not allowed is
    // refused before the daemon is asked anything, and a range that is allowed
    // is said out loud: it moves every device's IPv4 address, and software that
    // predates it cannot read the network.
    let ipv4_range = option(rest, "--ipv4-range");
    if let Some(range) = daemon::founding::ipv4_range(ipv4_range.as_deref())? {
        println!("every device in this network derives its IPv4 address in {range}.");
        println!(
            "devices running peerfectly older than this change cannot read a network that sets a \
             range."
        );
        println!();
    }

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
        rendezvous: option(rest, "--rendezvous"),
        certificate,
        ipv4_range,
    })
}

/// The network an option named, where one was given.
///
/// Read from the arguments rather than passed down, because the commands that
/// take one are reached by several paths and every one of them would otherwise
/// have to thread it.
fn network_option() -> Option<String> {
    let rest: Vec<String> = std::env::args().skip(2).collect();
    option(&rest, "--network")
}

/// Builds the joining command from what a person typed.
fn joining_from(rest: &[String]) -> Result<daemon::control::Command, String> {
    // No name for the network. A person starting a join has not seen it and does
    // not know its suffix; the daemon writes under a name of its own and keeps the
    // network under one taken from the network itself once it arrives.
    let relay = option(rest, "--relay")
        .or_else(|| rest.first().filter(|word| !word.starts_with("--")).cloned())
        .ok_or_else(|| format!("usage: {JOIN_USAGE}"))?;
    Ok(daemon::control::Command::Join {
        relay,
        name: option(rest, "--name").unwrap_or_else(default_name),
    })
}

/// Shows a relay's certificate and asks whether to pin it.
///
/// Founding and moving a relay ask with the same words, because they are asking
/// the same question: is this the relay you mean, or whatever answered first.
fn pin_confirmed(relay: &str, fingerprint: &str, der_len: usize) -> bool {
    println!();
    println!("  SHA-256  {fingerprint}");
    println!("  {der_len} bytes of DER");
    println!();
    println!("Nothing has checked that this is your relay. Anyone in the path could");
    println!("have answered. On the relay host, the same certificate prints as:");
    println!();
    println!("  openssl x509 -in <the relay's cert file> -noout -fingerprint -sha256");
    println!();
    print!("Pin this certificate for {relay}? [yes/no] ");
    said_yes()
}

/// Reads one line a person types, trimmed. `None` when there is nothing to read.
fn read_a_line() -> Option<String> {
    use std::io::{BufRead as _, Write as _};

    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).ok()? == 0 {
        return None;
    }
    let typed = line.trim().to_owned();
    if typed.is_empty() { None } else { Some(typed) }
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

/// How `found` is spelled, in one place so the usage and the refusal agree.
const FOUND_USAGE: &str = "peerfectly found <network> [--name N] [--suffix S] [--relay URL] \
     [--rendezvous URL] \
                           [--relay-cert FILE | --no-relay-cert] [--ipv4-range A.B.C.D/N]";

/// The name a device proposes when a person did not choose one.
///
/// The machine's own name, because that is what a person will look for in a list
/// and what they would have typed. The admin can choose another.
fn default_name() -> String {
    // Windows says it in `COMPUTERNAME`; elsewhere a shell may export
    // `HOSTNAME`, and the machine keeps it in `/etc/hostname`.
    ["COMPUTERNAME", "HOSTNAME"]
        .iter()
        .find_map(|variable| std::env::var(variable).ok())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "device".to_owned())
}

/// How `join` is spelled, in one place so the usage and the refusal agree.
const JOIN_USAGE: &str = "peerfectly join --relay URL [--name NAME]";

/// How `admit` is spelled, in one place so the usage and the refusal agree.
const ADMIT_USAGE: &str = "peerfectly admit <the payload the joining device printed>";

const REVOKE_USAGE: &str = daemon::control::Command::REVOKE_USAGE;

/// How `forget` is spelled, in one place so the usage and the refusal agree.
const FORGET_USAGE: &str = daemon::control::Command::FORGET_USAGE;

/// What a person can ask for.
fn usage(privileged: &str) -> String {
    use daemon::control::Command;

    let needs = format!("  (needs {privileged})");

    let mut out = String::from("usage: peerfectly <command> [network]\n\ncommands:\n");
    for (word, takes_a_network) in Command::ALL {
        // Asked of the command rather than listed here, so a command added to
        // `ALL` cannot come with the wrong note beside it. Built with no network
        // in mind, which is why it is parsed with `None`: the note is a property
        // of the word, not of which network it acts on.
        let note = match Command::parse(word, None) {
            Ok(command) if command.needs_administrator() => needs.as_str(),
            _ => "",
        };
        let network = if *takes_a_network { " [network]" } else { "" };
        out.push_str(&format!("  {word}{network}{note}\n"));
    }
    // Founding and joining are the daemon's commands now, but they take
    // arguments, so they are not among the single words `ALL` holds. Listed here
    // rather than derived, for that reason alone — not because they happen
    // anywhere else.
    out.push_str(&format!("\n  {FOUND_USAGE}{needs}\n"));
    out.push_str(&format!("  {JOIN_USAGE}{needs}\n"));
    out.push_str(&format!("  {ADMIT_USAGE}\n"));
    out.push_str(&format!(
        "  {REVOKE_USAGE}{needs}
"
    ));
    out.push_str(&format!(
        "  {FORGET_USAGE}
"
    ));
    out.push_str(&format!("  {}{needs}\n", daemon::control::Command::RELAY_USAGE));
    out.push_str(&format!("  {}\n", daemon::control::Command::RENDEZVOUS_USAGE));
    out.push_str(&format!("  peerfectly expose <network> tcp|udp <port>{needs}\n"));
    out.push_str(&format!("  peerfectly unexpose <network> tcp|udp <port>{needs}\n"));
    out.push_str("  peerfectly exposed [network]\n");
    out
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use daemon::control::Command;

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
    }

    /// `peerfectly rendezvous` is listed, and reads what a person types.
    #[test]
    fn the_rendezvous_command_is_listed_and_read() {
        let usage = super::usage("Administrator");
        assert!(usage.contains("peerfectly rendezvous"), "{usage}");
        assert!(
            super::usage("sudo")
                .contains("peerfectly expose <network> tcp|udp <port>  (needs sudo)")
        );
        assert!(!super::usage("sudo").contains("Administrator"), "the platform's own word, only");
        assert_eq!(
            Ok(Command::ChangeRendezvous {
                network: Some("casa".to_owned()),
                rendezvous: Some("https://203.0.113.10:8444".to_owned()),
            }),
            Command::rendezvous_change(&words("https://203.0.113.10:8444 --network casa"))
        );
    }

    fn certificate_of(command: &Command) -> daemon::control::Certificate {
        match command {
            Command::Found { certificate, .. } => certificate.clone(),
            other => panic!("expected a founding, got {other:?}"),
        }
    }

    /// A relay and no argument about it: the certificate is fetched.
    ///
    /// The other way round produces a network that can never admit anybody —
    /// admitting verifies against the system's roots when the network pins
    /// nothing, and cannot reach a relay whose certificate they refuse. A person
    /// who has not thought about it must not land there by default.
    #[test]
    fn a_relay_has_its_certificate_fetched_without_being_asked_for() {
        let command = founding_from(&words("casa --relay https://relay.example:443")).unwrap();
        assert_eq!(daemon::control::Certificate::FromTheRelay, certificate_of(&command));
    }

    /// And without a relay there is nothing to fetch, so nothing is asked for.
    #[test]
    fn no_relay_fetches_nothing() {
        let command = founding_from(&words("casa")).unwrap();
        assert_eq!(daemon::control::Certificate::None, certificate_of(&command));
    }

    /// A person can still say no, and it takes saying so.
    #[test]
    fn declining_is_possible_and_explicit() {
        let command =
            founding_from(&words("casa --relay https://relay.example:443 --no-relay-cert"))
                .unwrap();
        assert_eq!(daemon::control::Certificate::None, certificate_of(&command));
    }

    /// Naming a certificate and refusing one at the same time is a mistake, not
    /// a precedence puzzle to resolve quietly.
    #[test]
    fn a_certificate_and_a_refusal_together_are_refused() {
        let refusal =
            founding_from(&words("casa --relay https://r:443 --relay-cert c.pem --no-relay-cert"))
                .unwrap_err();
        assert!(refusal.contains("one or the other"), "{refusal}");
    }

    #[test]
    fn the_usage_names_the_way_to_decline() {
        assert!(super::FOUND_USAGE.contains("--no-relay-cert"));
        assert!(
            !super::FOUND_USAGE.contains("--fetch-relay-cert"),
            "fetching is no longer something to ask for"
        );
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
            vec![0xa0],
            heads,
            depths,
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
        assert_eq!(std::process::ExitCode::FAILURE, cli.wait_for_the_code().await);
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

        let outcome = cli.ask_and_sign(Command::Replace).await.unwrap();

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
            rendezvous: None,
            certificate: daemon::control::Certificate::None,
            ipv4_range: None,
        };

        let outcome = cli.ask_and_sign(founding).await.unwrap();

        assert_eq!(Outcome::Done, outcome);
        assert_eq!(0, custody.asked.load(Ordering::SeqCst), "nobody was asked again");
        assert_eq!(1, custody.used.load(Ordering::SeqCst), "the key just made signed");
        assert_eq!(Some(vec![vec![8], vec![8]]), signed(&daemon.sent()));
        assert!(custody.dropped.load(Ordering::SeqCst), "and it is gone");
    }

    /// **A key made before a pause is not kept across it.** A join makes its key
    /// and then waits for the other device; the unlocked key is dropped at that
    /// answer, and nothing signs with it.
    #[tokio::test]
    async fn a_key_just_made_is_dropped_when_the_answer_is_not_its_batch() {
        let daemon = Scripted::answering(vec![
            Outcome::NeedsKey(KeyWanted {
                id: "k1".to_owned(),
                name: "peerfectly.casa.signing".to_owned(),
                network: "casa".to_owned(),
            }),
            Outcome::Enrolling,
        ]);
        let custody = Willing { unlocks: true, ..Willing::default() };
        let cli = Cli { channel: &daemon, custody: &custody, extras: Extras::default() };

        let outcome = cli.ask_and_sign(Command::Waiting).await.unwrap();

        assert_eq!(Outcome::Enrolling, outcome);
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

//! A batch of signatures, read off its bytes: whether it holds together, and
//! what it says.
//!
//! An act can need several signatures — an operation and the snapshot over the
//! roster once it is in; a revocation and the admission that replaces it — and
//! the daemon prepares all of them before any is made. This is where the command
//! line decides whether to put that batch in front of a person at all, and what
//! to tell them it is.
//!
//! # Nothing here believes the daemon about what an act is
//!
//! The daemon is the component this design stopped trusting with the key, so it
//! is not trusted with the words either. Every sentence below is read from the
//! bytes that will be signed, or from what the person typed. The one word the
//! daemon supplies beside them is the network's label, which says *whose key*
//! and nothing about *what act* — and where the person typed a label, the two
//! must agree.
//!
//! # A batch that does not hold together is not signed
//!
//! Before anything is shown, the batch must be one act: a single operation, or a
//! revocation followed by the admission built on it, each after the first naming
//! the one before as a parent; at most one snapshot, last, covering them; all of
//! it for one network. Anything else is refused whole, and the daemon is told
//! nothing was signed. The checks are here, in the one portable copy, because a
//! check written once per platform is a check one platform forgets.

use daemon::control::{Command, MOST_IN_A_BATCH, SignaturesWanted, SigningKind, ToSign};
use roster::id::NetworkId;
use roster::snapshot::Snapshot;
use roster::types::{NetworkParams, OperationBody, OperationCore};

/// One item of a batch, read.
#[derive(Debug, Clone)]
pub(crate) enum Read {
    /// A roster operation.
    Operation(Box<OperationCore>),
    /// A roster snapshot.
    Snapshot(Snapshot),
    /// A joining device's proof that it holds the key it presented.
    Possession,
}

/// What a person is told about one item: the act, and what it will mean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Described {
    /// What the item does, in a line.
    pub act: String,
    /// What follows from it — which acts cannot be undone, who will reach whom.
    pub consequence: String,
}

/// Reads one item off its bytes, or nothing where they are not what the item
/// claims to be.
pub(crate) fn read(item: &ToSign) -> Option<Read> {
    match item.kind {
        SigningKind::Operation => {
            OperationCore::decode(&item.payload).ok().map(|core| Read::Operation(Box::new(core)))
        }
        SigningKind::Snapshot => Snapshot::decode(&item.payload).ok().map(Read::Snapshot),
        // A proof of possession carries no artifact: its signature is the whole
        // of it. One that carries something is not one.
        SigningKind::Possession => item.payload.is_empty().then_some(Read::Possession),
        _ => None,
    }
}

/// The network an operation belongs to.
///
/// A founding names none, because it is what creates one: the network's id is
/// the founding operation's own.
fn network_of(core: &OperationCore) -> NetworkId {
    if matches!(core.body, OperationBody::CreateNetwork { .. }) {
        NetworkId::from_bytes(*core.id().as_bytes())
    } else {
        core.network
    }
}

/// The network label the person typed, if they typed one.
fn typed_label(asked: &Command) -> Option<&str> {
    match asked {
        Command::Found { label, .. } => Some(label.as_str()),
        Command::Revoke { network, .. }
        | Command::ChangeRelay { network, .. }
        | Command::ChangeRendezvous { network, .. }
        | Command::Admit { network, .. } => network.as_deref(),
        _ => None,
    }
}

/// Whether an operation is the act a person's command asks for.
///
/// The second half of not trusting the daemon with the words. Reading the act
/// off the bytes stops a description from lying; this stops the *bytes* from
/// being about something else. A person who typed `revoke laptop` and is handed
/// a promotion has been handed somebody else's act, and the only component that
/// knows what they typed is this one.
///
/// **Down to the values typed**, where the bytes carry them: the reason a
/// revocation gives, the name a founding gives this device, the rendezvous or
/// relay a settings change moves to. A daemon that kept the act and changed the
/// address would otherwise have it signed.
///
/// A command that is not one of the acts below imposes no expectation: an
/// admission is confirmed rather than named, and there is nothing to compare.
pub(crate) fn matches_what_was_asked(command: &Command, core: &OperationCore) -> bool {
    match command {
        Command::Revoke { reason, .. } => matches!(
            &core.body,
            OperationBody::RevokeDevice { reason: signed, .. } if signed == reason.trim()
        ),
        Command::Found { name, .. } => matches!(
            &core.body,
            OperationBody::CreateNetwork { device, .. } if device.name == *name
        ),
        Command::ChangeRendezvous { rendezvous, .. } => matches!(
            &core.body,
            OperationBody::SetNetwork(params) if params.rendezvous == *rendezvous
        ),
        Command::ChangeRelay { relay, .. } => matches!(
            &core.body,
            OperationBody::SetNetwork(params)
                if params.relay.as_deref().is_some_and(|signed| daemon::relay::same_relay(signed, relay))
        ),
        _ => true,
    }
}

/// Whether the batch is one act this command signs, and the items read.
///
/// # Errors
///
/// Why it is not, in words for the person — and nothing is signed.
pub(crate) fn holds_together(
    asked: &Command,
    wanted: &SignaturesWanted,
) -> Result<Vec<Read>, String> {
    let count = wanted.items.len();
    if count == 0 || count > MOST_IN_A_BATCH {
        return Err(format!(
            "the daemon asked for {count} signatures at once, which is not an act this command \
             signs"
        ));
    }
    if let Some(typed) = typed_label(asked)
        && typed != wanted.network
    {
        return Err(format!(
            "the daemon asked for a signature with the key of `{}`, and you named `{typed}`",
            daemon::control::shown(&wanted.network)
        ));
    }

    let read: Vec<Read> =
        wanted.items.iter().map(read).collect::<Option<_>>().ok_or_else(|| {
            "the daemon asked for a signature over something this command could not read".to_owned()
        })?;

    // A proof of possession is a batch of its own.
    if read.iter().any(|item| matches!(item, Read::Possession)) {
        return if count == 1 {
            Ok(read)
        } else {
            Err("a proof of possession came with other things to sign".to_owned())
        };
    }

    let operations: Vec<&OperationCore> = read
        .iter()
        .filter_map(|item| match item {
            Read::Operation(core) => Some(core.as_ref()),
            _ => None,
        })
        .collect();
    let snapshots: Vec<&Snapshot> = read
        .iter()
        .filter_map(|item| match item {
            Read::Snapshot(body) => Some(body),
            _ => None,
        })
        .collect();

    let Some(first) = operations.first() else {
        return Err(
            "the daemon asked for a snapshot on its own, with no act for it to follow".to_owned()
        );
    };
    if snapshots.len() > 1 {
        return Err("the daemon asked for more than one snapshot at once".to_owned());
    }
    if !snapshots.is_empty() && !matches!(read.last(), Some(Read::Snapshot(_))) {
        return Err("the snapshot does not come last, after the acts it covers".to_owned());
    }

    // One network.
    let network = network_of(first);
    if operations.iter().any(|core| network_of(core) != network)
        || snapshots.iter().any(|body| body.network != network)
    {
        return Err("the things to sign belong to more than one network".to_owned());
    }

    // One act: a chain, each after the first built on the one before.
    for pair in operations.windows(2) {
        if let [before, after] = pair
            && !after.parents.contains(&before.id())
        {
            return Err("the acts to sign do not follow one another".to_owned());
        }
    }
    match operations.as_slice() {
        [_] => {}
        [before, after] => {
            let replacing = matches!(before.body, OperationBody::RevokeDevice { .. })
                && matches!(after.body, OperationBody::AddDevice(_))
                && matches!(asked, Command::Confirm | Command::Replace);
            if !replacing {
                return Err("two acts were asked for where this command signs one".to_owned());
            }
        }
        _ => return Err("more acts were asked for than this command signs".to_owned()),
    }
    if !matches_what_was_asked(asked, first) {
        return Err("the act to be signed is not the act that was asked for".to_owned());
    }

    if let (Some(body), Some(last)) = (snapshots.first(), operations.last())
        && !body.heads.contains(&last.id())
    {
        return Err("the snapshot does not cover the act it comes with".to_owned());
    }

    Ok(read)
}

/// What one item says, in plain words, with what follows from it.
///
/// `network` is this machine's label for the network; `asked` is what the person
/// typed, for the one thing the bytes do not carry: the name they called a
/// device they are revoking.
pub(crate) fn describe(item: &Read, network: &str, asked: &Command) -> Described {
    let network = named(network);
    match item {
        Read::Possession => Described {
            act: "prove to the admitting device that this device holds the key it presented"
                .to_owned(),
            consequence: "no roster changes".to_owned(),
        },
        Read::Snapshot(body) => Described {
            act: format!("record {network}'s current membership (snapshot {})", body.seq),
            consequence: "routine: the other devices confirm the roster against it; nobody's \
                          access changes"
                .to_owned(),
        },
        Read::Operation(core) => operation(core, &network, asked),
    }
}

/// What an operation says.
fn operation(core: &OperationCore, network: &str, asked: &Command) -> Described {
    let short = |id: &roster::id::DeviceId| daemon::control::short_id(id);
    match &core.body {
        OperationBody::CreateNetwork { device, .. } => Described {
            act: format!(
                "found {network}, with this device named `{}` as its first admin",
                daemon::control::shown(&device.name)
            ),
            consequence: "this key signs every admin act for it from now on".to_owned(),
        },
        OperationBody::AddDevice(spec) => {
            let id = spec.device_id().map(|device| short(&device)).unwrap_or_default();
            let role =
                if spec.role == roster::types::Role::Admin { "an admin" } else { "a member" };
            Described {
                act: format!("admit `{}` ({id}) as {role}", daemon::control::shown(&spec.name)),
                consequence: format!(
                    "it will reach the devices in {network}, and they will reach it"
                ),
            }
        }
        OperationBody::RevokeDevice { device, reason } => {
            // The name the person typed, where they typed one: the bytes carry
            // the device's id and the reason, not what it was called.
            let named = match asked {
                Command::Revoke { target: daemon::control::Target::Name(name), .. } => {
                    format!("`{}` ", daemon::control::shown(name))
                }
                _ => String::new(),
            };
            Described {
                act: format!(
                    "revoke {named}({}): {}",
                    short(device),
                    daemon::control::shown(reason)
                ),
                consequence: "permanent: a revoked device never comes back under the same \
                              identity"
                    .to_owned(),
            }
        }
        OperationBody::Promote { device, founder } => Described {
            act: format!(
                "make {} an admin{}",
                short(device),
                if *founder { " and a founder" } else { "" }
            ),
            consequence: "it will be able to admit and revoke devices".to_owned(),
        },
        OperationBody::Demote { device } => Described {
            act: format!("make {} a member", short(device)),
            consequence: "it will no longer be able to admit or revoke devices".to_owned(),
        },
        OperationBody::Rename { device, name } => Described {
            act: format!("rename {} to `{}`", short(device), daemon::control::shown(name)),
            consequence: "the name every device uses for it changes".to_owned(),
        },
        OperationBody::SetNetwork(params) => Described {
            act: format!("change {network}'s settings to: {}", settings(params)),
            consequence: format!("every device in {network} follows this"),
        },
    }
}

/// A network's settings, as a person would want them read out.
fn settings(params: &NetworkParams) -> String {
    let relay = params.relay.as_deref().map_or_else(
        || "no relay".to_owned(),
        |relay| format!("relay {}", daemon::control::shown(relay)),
    );
    let pinned = params.relay_cert.as_deref().map_or_else(
        || "its certificate not pinned".to_owned(),
        |der| format!("its certificate pinned as {}", daemon::relay::fingerprint(der)),
    );
    let rendezvous = params.rendezvous.as_deref().map_or_else(
        || "no rendezvous".to_owned(),
        |address| format!("rendezvous {}", daemon::control::shown(address)),
    );
    let mut said = format!("{relay} ({pinned}), {rendezvous}, IPv4 range {}", params.ipv4_range());
    if let Some(leaving) = &params.leaving {
        let until = std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::from_millis(leaving.until))
            .map_or_else(String::new, |at| format!(" until {}", daemon::drawing::when(at)));
        said.push_str(&format!(
            "; devices keep using {} too{until}, so the ones switched off can still find the \
             network",
            daemon::control::shown(&leaving.relay)
        ));
    }
    said
}

/// The one-line summary of a batch, for a platform prompt that can carry a line.
pub(crate) fn summary(read: &[Read], network: &str, asked: &Command) -> String {
    let acts: Vec<String> = read.iter().map(|item| describe(item, network, asked).act).collect();
    format!("peerfectly · {}: {}", named(network), acts.join("; "))
}

/// How a network is named to a person: as this machine names it, or — while it
/// is being joined and has no name here yet — as the one being joined.
pub(crate) fn named(network: &str) -> String {
    if network.is_empty() {
        "the network being joined".to_owned()
    } else {
        daemon::control::shown(network).to_string()
    }
}

/// What is printed before anything is asked: whose key, and every act with its
/// consequence.
pub(crate) fn listed(read: &[Read], network: &str, asked: &Command) -> String {
    let shown = named(network);
    let mut out = if matches!(read, [Read::Possession]) {
        format!("{shown}: a proof to sign with this device's own signing key\n\n")
    } else {
        let acts = read.len();
        format!(
            "{shown}: {acts} act{} to sign with this network's admin key\n\n",
            if acts == 1 { "" } else { "s" }
        )
    };
    for (number, item) in read.iter().enumerate() {
        let described = describe(item, network, asked);
        out.push_str(&format!(
            "  {}. {}\n     {}\n",
            number.saturating_add(1),
            described.act,
            described.consequence
        ));
    }
    out
}

#[cfg(test)]
mod tests;

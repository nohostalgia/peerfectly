//! The service's log: what is written, and what may never be.
//!
//! The daemon emits `tracing` events; where they go is each platform's — a file
//! on Windows, standard error for journald on Linux. This is the part both
//! share.
//!
//! # Only the daemon's own messages
//!
//! The transport library logs through `tracing` too, and its messages carry
//! node identities and addresses. A sink keeps what [`ours`] accepts and drops
//! everything else, whatever its level.
//!
//! # Chosen fields, never a value as it arrived
//!
//! An act is logged by its word, the network and the kind of outcome — never
//! the command, which can carry an enrolment payload, a confirmation code or a
//! signature. A fault's cause is passed through [`scrubbed`] first, so that an
//! identifier embedded in a library's error reaches the log as a prefix only.
//! Nothing resolved or forwarded is ever given to an event: the resolver
//! records I/O failures, not queries.

/// The crates whose events the service's log keeps: the portable daemon, and each
/// platform's daemon and its service program.
pub const TARGETS: [&str; 4] = ["daemon", "windows_daemon", "linux_daemon", "peerfectlyd"];

/// Whether an event from `target` belongs in the service's log.
///
/// By crate, so `daemon::node` is ours and `daemon_something` is not.
#[must_use]
pub fn ours(target: &str) -> bool {
    TARGETS.iter().any(|crate_name| {
        target
            .strip_prefix(crate_name)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
    })
}

/// How many hex digits of an identifier the log keeps: a short id's worth.
const KEPT_DIGITS: usize = 16;

/// `text` with every long run of hex digits cut to a short id's length.
///
/// A device id, a key id, an operation id or a transport key written out in
/// full is a stable identifier of a device or a key; the log is readable by
/// every administrator of the machine, and a prefix is enough to match it
/// against `status`.
#[must_use]
pub fn scrubbed(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() > KEPT_DIGITS {
            out.push_str(run.get(..KEPT_DIGITS).unwrap_or_default());
            out.push('…');
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for character in text.chars() {
        if character.is_ascii_hexdigit() {
            run.push(character);
        } else {
            flush(&mut run, &mut out);
            out.push(character);
        }
    }
    flush(&mut run, &mut out);
    out
}

/// The events emitted on this thread while a guard is held, one line each.
///
/// For tests: a subscriber of a few lines rather than a dependency, and one that
/// records every field so a test can assert what is absent.
#[cfg(test)]
pub(crate) mod captured {
    use core::fmt::Write as _;
    use std::sync::{Arc, Mutex};

    /// What was captured.
    #[derive(Clone, Default)]
    pub(crate) struct Lines(Arc<Mutex<Vec<String>>>);

    impl Lines {
        pub(crate) fn all(&self) -> Vec<String> {
            self.0.lock().map(|lines| lines.clone()).unwrap_or_default()
        }
    }

    struct Capture(Lines);

    struct Fields<'a>(&'a mut String);

    impl tracing::field::Visit for Fields<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }

    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut line = event.metadata().target().to_owned();
            event.record(&mut Fields(&mut line));
            if let Ok(mut lines) = (self.0).0.lock() {
                lines.push(line);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Captures until the guard is dropped.
    pub(crate) fn capture() -> (Lines, tracing::subscriber::DefaultGuard) {
        let lines = Lines::default();
        let guard = tracing::subscriber::set_default(Capture(lines.clone()));
        (lines, guard)
    }
}

#[cfg(test)]
mod tests {
    use super::{ours, scrubbed};

    /// **No event is given a payload, a code, a key, a query or a whole command.**
    /// Read off every event in this crate's source, so an event added tomorrow
    /// is held to it too; and every cause is scrubbed on the way in.
    #[test]
    fn no_event_is_given_what_must_never_be_logged() {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut events = 0;
        for entry in std::fs::read_dir(source).into_iter().flatten().flatten() {
            let text = std::fs::read_to_string(entry.path()).unwrap_or_default();
            let code = crate::code_of(&text);
            for event in code.split("tracing::").skip(1) {
                let Some(level) = ["info!", "warn!", "error!", "debug!", "trace!"]
                    .into_iter()
                    .find(|level| event.starts_with(level))
                else {
                    continue;
                };
                events += 1;
                let arguments = within_parentheses(event.get(level.len()..).unwrap_or_default());
                for never in
                    ["payload", "code", "signature", "public", "query", "question", "command"]
                {
                    assert!(
                        !arguments.to_lowercase().contains(never),
                        "`{never}` given to an event in {:?}: {arguments}",
                        entry.file_name()
                    );
                }
                if arguments.contains("cause") || arguments.contains("detail") {
                    assert!(
                        arguments.contains("scrubbed("),
                        "a cause reaches the log unscrubbed in {:?}: {arguments}",
                        entry.file_name()
                    );
                }
            }
        }
        assert!(events >= 5, "the events were not found, so nothing was checked: {events}");
    }

    /// What a macro call is given: from its opening parenthesis to the one that
    /// closes it.
    fn within_parentheses(call: &str) -> &str {
        let mut depth = 0_usize;
        for (at, character) in call.char_indices() {
            match character {
                '(' => depth = depth.saturating_add(1),
                ')' if depth <= 1 => return call.get(..=at).unwrap_or(call),
                ')' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        call
    }

    #[test]
    fn only_the_daemons_own_targets_are_kept() {
        for kept in ["daemon", "daemon::node", "windows_daemon::service"] {
            assert!(ours(kept), "{kept}");
        }
        for dropped in ["iroh", "iroh::magicsock", "daemonic", "iroh_relay::daemon", ""] {
            assert!(!ours(dropped), "{dropped}");
        }
    }

    #[test]
    fn a_full_identifier_is_cut_to_a_prefix() {
        let id = "3d4e5f6a7b8c9d0e".repeat(4);
        let said = scrubbed(&format!("DeviceId({id}): the session is closed"));

        assert_eq!(said, "DeviceId(3d4e5f6a7b8c9d0e…): the session is closed");
        assert!(!said.contains(&id));
    }

    #[test]
    fn ordinary_words_and_short_numbers_are_left_alone() {
        let text = "fd01::2 refused 1200 bytes; face cafe 443";
        assert_eq!(scrubbed(text), text);
    }
}

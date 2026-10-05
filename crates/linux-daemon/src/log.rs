//! The daemon's log on Linux: standard error, where systemd puts it in the
//! journal.
//!
//! The same events as on Windows and the same filter: the daemon's own, at
//! `info` or worse, and nothing from the libraries under it, whose events carry
//! node identities and addresses (`daemon::logging`). What reaches an event is
//! already chosen fields and scrubbed causes; the sink adds nothing but the
//! line.
//!
//! **No timestamp under systemd.** The journal stamps every line itself, and a
//! second stamp is noise that disagrees with the first by the time it took to
//! arrive. systemd says it is listening by setting `JOURNAL_STREAM`.

use tracing_subscriber::Layer as _;
use tracing_subscriber::layer::SubscriberExt as _;

/// Whether an event belongs in the log.
fn kept(meta: &tracing::Metadata<'_>) -> bool {
    daemon::logging::ours(meta.target()) && *meta.level() <= tracing::Level::INFO
}

/// Whether standard error goes to the journal.
#[must_use]
pub fn to_the_journal() -> bool {
    std::env::var_os("JOURNAL_STREAM").is_some()
}

/// Sends the daemon's log to standard error.
///
/// # Errors
///
/// When a log was already installed.
pub fn to_standard_error() -> Result<(), String> {
    let installed = if to_the_journal() {
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(false)
            .without_time()
            .with_writer(std::io::stderr)
            .with_filter(tracing_subscriber::filter::filter_fn(kept));
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer))
    } else {
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(false)
            .with_writer(std::io::stderr)
            .with_filter(tracing_subscriber::filter::filter_fn(kept));
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer))
    };
    installed.map_err(|cause| cause.to_string())
}

#[cfg(test)]
mod tests {
    /// This crate's events are the daemon's own, and reach the log.
    #[test]
    fn this_crates_events_are_kept() {
        assert!(daemon::logging::ours("linux_daemon::programs::daemon"));
        assert!(!daemon::logging::ours("linux_daemonic"));
        assert!(!daemon::logging::ours("tss_esapi::context"), "the TPM library's are not");
    }
}

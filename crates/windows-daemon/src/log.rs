//! Where the service's log is written on Windows.
//!
//! The daemon emits events (see `daemon::logging`); this is the sink. As a
//! service, a file under `%ProgramData%\peerfectly\logs`, which carries the same
//! access control as the networks: SYSTEM and administrators only, because it
//! records what every person on the machine asked for. In the foreground,
//! standard error, where the person running it is watching.
//!
//! # Bounded
//!
//! The file is rotated at [`ROTATES_AT`], keeping [`OLD_KEPT`] old ones, so the
//! log never takes more than four mebibytes whatever runs for how long.
//!
//! # Only the daemon's own events
//!
//! Filtered by `daemon::logging::ours`, so the transport library's events —
//! which carry node identities and addresses — never reach the file, whatever
//! their level.

use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tracing_subscriber::Layer as _;
use tracing_subscriber::layer::SubscriberExt as _;

/// The log's file name.
pub const FILE: &str = "peerfectlyd.log";

/// How large the file grows before it is rotated.
pub const ROTATES_AT: u64 = 1024 * 1024;

/// How many rotated files are kept beside it.
pub const OLD_KEPT: u32 = 3;

/// A file that is rotated when a line would take it past its bound.
#[derive(Debug)]
pub struct Rotating {
    /// Where the file and its old ones are.
    directory: PathBuf,
    /// Past this, the next line starts a new file.
    limit: u64,
    /// The file being written and how large it is, once opened.
    open: Mutex<Option<(File, u64)>>,
}

impl Rotating {
    /// The log in `directory`, bounded as the service's is.
    #[must_use]
    pub fn in_directory(directory: &Path) -> Self {
        Self::bounded(directory, ROTATES_AT)
    }

    /// The same, with another bound. For tests, which would not write a
    /// mebibyte to see it rotate.
    #[must_use]
    pub fn bounded(directory: &Path, limit: u64) -> Self {
        Self { directory: directory.to_path_buf(), limit, open: Mutex::new(None) }
    }

    /// The file being written.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.directory.join(FILE)
    }

    /// The `n`th old file.
    fn old(&self, n: u32) -> PathBuf {
        self.directory.join(format!("{FILE}.{n}"))
    }

    /// Writes one line, rotating first if it would pass the bound.
    fn write_line(&self, line: &[u8]) -> std::io::Result<()> {
        let mut open =
            self.open.lock().map_err(|_| std::io::Error::other("the log is poisoned"))?;
        let length = u64::try_from(line.len()).unwrap_or(u64::MAX);

        if let Some((_, size)) = open.as_ref()
            && *size > 0
            && size.saturating_add(length) > self.limit
        {
            *open = None;
            self.rotate();
        }

        if open.is_none() {
            let file = File::options().create(true).append(true).open(self.path())?;
            let size = file.metadata().map_or(0, |meta| meta.len());
            *open = Some((file, size));
        }
        if let Some((file, size)) = open.as_mut() {
            file.write_all(line)?;
            *size = size.saturating_add(length);
        }
        Ok(())
    }

    /// Moves each old file one along, dropping the oldest, and the current one
    /// to the first. Failures are ignored: a log that cannot rotate keeps
    /// writing, and a daemon must not stop over its log.
    fn rotate(&self) {
        let _ = std::fs::remove_file(self.old(OLD_KEPT));
        for n in (1..OLD_KEPT).rev() {
            let _ = std::fs::rename(self.old(n), self.old(n.saturating_add(1)));
        }
        let _ = std::fs::rename(self.path(), self.old(1));
    }
}

/// One event's line, handed to [`Rotating`] whole.
pub struct Line<'a>(&'a Rotating);

impl std::io::Write for Line<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.write_line(buffer)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Rotating {
    type Writer = Line<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        Line(self)
    }
}

/// Whether an event belongs in the log: the daemon's own, informational or
/// worse.
fn kept(meta: &tracing::Metadata<'_>) -> bool {
    daemon::logging::ours(meta.target()) && *meta.level() <= tracing::Level::INFO
}

/// A subscriber writing the daemon's own events to `writer`.
pub fn writing_to<W>(writer: W) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(false)
        .with_writer(writer)
        .with_filter(tracing_subscriber::filter::filter_fn(kept));
    tracing_subscriber::registry().with(layer)
}

/// The log's directory under a machine's program data: `peerfectly\logs`.
///
/// The product's own directory is made protected first. Made the other way
/// round, it would be created as a parent with whatever `%ProgramData%` grants,
/// and never protected afterwards, since protecting an existing directory is
/// not something this does quietly.
///
/// # Errors
///
/// When either directory cannot be made carrying its access control.
#[cfg(windows)]
pub fn directory_under(base: &Path) -> Result<PathBuf, String> {
    let root = base.join(daemon::limits::PRODUCT);
    crate::platform::protected::create_protected(&root)?;
    let logs = root.join("logs");
    crate::platform::protected::create_protected(&logs)?;
    Ok(logs)
}

/// Sends the service's log to its file under `%ProgramData%`.
///
/// # Errors
///
/// When the environment does not say where program data is, the directory
/// cannot be made, or a log was already installed.
#[cfg(windows)]
pub fn to_the_file() -> Result<PathBuf, String> {
    let base = std::env::var_os("PROGRAMDATA")
        .ok_or("the environment does not say where the machine's own state belongs")?;
    let directory = directory_under(Path::new(&base))?;
    let writer = Rotating::in_directory(&directory);
    let path = writer.path();
    tracing::subscriber::set_global_default(writing_to(writer))
        .map_err(|cause| cause.to_string())?;
    Ok(path)
}

/// Sends the service's log to standard error, for a daemon run in a console.
///
/// # Errors
///
/// When a log was already installed.
pub fn to_standard_error() -> Result<(), String> {
    tracing::subscriber::set_global_default(writing_to(std::io::stderr))
        .map_err(|cause| cause.to_string())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::{FILE, OLD_KEPT, Rotating, writing_to};

    /// **The transport library's events never reach the file.** They carry node
    /// identities and addresses.
    #[test]
    fn another_targets_event_is_dropped() {
        let scratch = tempfile::tempdir().unwrap();
        let writer = Rotating::in_directory(scratch.path());
        let path = writer.path();

        tracing::subscriber::with_default(writing_to(writer), || {
            tracing::warn!(target: "iroh::magicsock", "the library said something");
            tracing::info!(target: "daemon::service", "the daemon said something");
            tracing::debug!(target: "daemon::node", "and something too fine for the log");
        });

        let written = std::fs::read_to_string(path).unwrap();
        assert!(written.contains("the daemon said something"), "{written}");
        assert!(!written.contains("the library"), "{written}");
        assert!(!written.contains("too fine"), "{written}");
    }

    /// **The log keeps its bound**: the file and three old ones, each no larger
    /// than the limit, and nothing beyond them.
    #[test]
    fn rotation_keeps_the_bound() {
        let scratch = tempfile::tempdir().unwrap();
        let writer = Rotating::bounded(scratch.path(), 100);
        for n in 0..60 {
            writer.write_line(format!("line {n:>12}\n").as_bytes()).unwrap();
        }

        for n in 1..=OLD_KEPT {
            let old = scratch.path().join(format!("{FILE}.{n}"));
            assert!(old.exists(), "{} kept", old.display());
            assert!(std::fs::metadata(&old).unwrap().len() <= 100);
        }
        assert!(!scratch.path().join(format!("{FILE}.{}", OLD_KEPT + 1)).exists(), "no more");
        assert!(std::fs::metadata(writer.path()).unwrap().len() <= 100);
        let newest = std::fs::read_to_string(writer.path()).unwrap();
        assert!(newest.contains("line           59"), "the newest line is current: {newest}");
    }

    /// **The product's directory is protected before the log's is made in it**,
    /// so neither is ever created with what `%ProgramData%` grants.
    ///
    /// The log's own directory cannot be made here: once its parent is for the
    /// system and administrators, a test that is not elevated may not write in
    /// it — which is the point. Its access control is read back on the machine,
    /// where the service runs as the system (VERIFICATION, 9.7).
    #[cfg(windows)]
    #[test]
    fn the_directory_is_for_the_system_and_administrators_only() {
        let scratch = tempfile::tempdir().unwrap();
        let _ = super::directory_under(scratch.path());

        let root = scratch.path().join(daemon::limits::PRODUCT);
        let carried = crate::platform::protected::describe(&root).unwrap();
        assert!(carried.starts_with("D:P"), "it inherits nothing: {carried}");
        assert!(carried.contains(";;;SY)") && carried.contains(";;;BA)"), "{carried}");
        assert_eq!(2, carried.matches("(A;").count(), "and nobody else: {carried}");

        let code = crate::code_of(include_str!("log.rs"));
        let root_first = code.find("create_protected(&root)").unwrap();
        let logs_after = code.find("create_protected(&logs)").unwrap();
        assert!(root_first < logs_after, "the parent is protected first");
    }
}

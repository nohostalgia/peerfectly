//! The control channel: a Unix socket at a fixed path.
//!
//! `/run/peerfectly/control.sock`, in a directory owned by root that only root can
//! create entries in — so the path is the daemon's, and a client that checks
//! the answering process is root (see [`connect_at`]) cannot be answered by
//! anything that took the path first.
//!
//! **Any local account may connect.** The socket is `0666`: who may do what is
//! decided per command, from the account the kernel reports, as on every
//! platform. Reading state is not a privileged act.
//!
//! A socket is not reachable from a browser, for the same reason the Windows
//! pipe is not: nothing a web page can make opens a Unix socket.

use std::io;
use std::os::unix::fs::{
    DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _,
};
use std::path::Path;

use tokio::net::{UnixListener, UnixStream};

/// The directory the socket lives in.
pub const DIRECTORY: &str = "/run/peerfectly";

/// The socket.
pub const SOCKET: &str = "/run/peerfectly/control.sock";

/// The lock only one daemon at a time holds.
pub const LOCK: &str = "/run/peerfectly/peerfectlyd.lock";

/// Takes the lock that makes this the only daemon, and holds it for as long as
/// what is returned lives — which is the process, since it is kept in `main`.
///
/// **First, before anything else is touched.** A second daemon that got as far
/// as the socket would remove the first one's, answer in its place, and bring
/// the same networks up on the same state: the testbed started one by hand
/// beside the service, and that is what it did. The kernel lets the lock go
/// when the process ends, crash included, so a lock is never stale.
///
/// # Errors
///
/// When another daemon holds it, or it cannot be taken.
pub fn only_one() -> io::Result<std::fs::File> {
    only_one_at(Path::new(LOCK))
}

/// The same, at a path the caller names — for tests.
///
/// # Errors
///
/// As [`only_one`].
pub fn only_one_at(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    if let Some(directory) = path.parent() {
        match std::fs::DirBuilder::new().mode(0o755).create(directory) {
            Ok(()) => {}
            Err(cause) if cause.kind() == io::ErrorKind::AlreadyExists => {}
            Err(cause) => return Err(named(cause, format!("making {}", directory.display()))),
        }
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|cause| named(cause, format!("opening {}", path.display())))?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
        |cause| {
            let cause = io::Error::from(cause);
            if cause.kind() == io::ErrorKind::WouldBlock {
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "another peerfectlyd is already running on this machine (it holds {})",
                        path.display()
                    ),
                )
            } else {
                named(cause, format!("locking {}", path.display()))
            }
        },
    )?;
    Ok(file)
}

/// Opens the control channel at its fixed path.
///
/// # Errors
///
/// When the directory is not root's, something that is not the daemon's socket
/// holds the path, or the socket cannot be made.
pub fn listen() -> io::Result<UnixListener> {
    listen_at(Path::new(SOCKET))
}

/// The same, at a path the caller names — for tests.
///
/// # Errors
///
/// As [`listen`].
pub fn listen_at(path: &Path) -> io::Result<UnixListener> {
    let directory = path.parent().unwrap_or_else(|| Path::new("/"));
    match std::fs::DirBuilder::new().mode(0o755).create(directory) {
        Ok(()) => {}
        Err(cause) if cause.kind() == io::ErrorKind::AlreadyExists => {}
        Err(cause) => return Err(named(cause, format!("making {}", directory.display()))),
    }
    let found = std::fs::metadata(directory)?;
    if found.uid() != 0 || found.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} must be root's and writable by nobody else (owner uid {}, mode {:o})",
                directory.display(),
                found.uid(),
                found.mode() & 0o7777
            ),
        ));
    }

    // A socket left by an earlier run is removed — only when it is a socket and
    // root's. Anything else at the path is somebody else's, and is refused.
    if let Ok(left) = std::fs::symlink_metadata(path) {
        if left.file_type().is_socket() && left.uid() == 0 {
            std::fs::remove_file(path)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} is held by something that is not this daemon's socket", path.display()),
            ));
        }
    }

    let listener = UnixListener::bind(path)
        .map_err(|cause| named(cause, format!("binding {}", path.display())))?;
    // Loosened from the umask, which opens no window: until this, fewer can
    // connect, not more.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

/// Connects to the daemon, and establishes that it is the daemon before
/// anything is sent.
///
/// # Errors
///
/// When nothing answers, or what answers is not running as root.
pub async fn connect() -> io::Result<UnixStream> {
    connect_at(Path::new(SOCKET)).await
}

/// The same, at a path the caller names — for tests.
///
/// # Errors
///
/// As [`connect`].
pub async fn connect_at(path: &Path) -> io::Result<UnixStream> {
    let stream = UnixStream::connect(path).await.map_err(|cause| {
        named(cause, "the daemon is not running, or is not reachable".to_owned())
    })?;
    let credentials = stream.peer_cred()?;
    crate::who::judge_server(credentials.uid(), credentials.pid())
        .map_err(|refusal| io::Error::new(io::ErrorKind::PermissionDenied, refusal))?;
    Ok(stream)
}

/// An error carrying what was being done.
fn named(cause: io::Error, doing: String) -> io::Error {
    io::Error::new(cause.kind(), format!("{doing}: {cause}"))
}

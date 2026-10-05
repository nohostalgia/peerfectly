//! The channel between the command line and the daemon.
//!
//! A named pipe, not a local TCP port.
//!
//! §7.3 warns that any page open in a browser can make requests to `127.0.0.1`,
//! which is why the eventual web UI will need a session token and an `Origin`
//! check. A named pipe is not reachable from a browser at all, so that whole
//! problem does not arise here — and a problem that does not arise cannot be got
//! wrong later.
//!
//! # The descriptor is written down, and read back
//!
//! It used to be the default one. Windows gives a pipe created without an
//! explicit descriptor an ACL granting its creator, `SYSTEM` and
//! `Administrators`, and while the daemon ran as a person that was the access it
//! wanted.
//!
//! **Running as the system broke it in a way no DACL could fix.** A privileged
//! process creates the pipe with a *high* integrity label, and Windows forbids a
//! process below that label from writing to the object — connecting to a duplex
//! pipe is a write. So `peerfectly status` from an ordinary console got
//! `ERROR_ACCESS_DENIED` while the DACL granted the very person asking, and every
//! command needed an elevated console. Reading state is not a privileged act, and
//! that was never the intended design.
//!
//! [`WHO_MAY_USE_IT`] says both halves: who may speak on the channel, and from
//! what integrity. It costs no `unsafe` here — `SecurityDescriptor::deserialize`
//! parses SDDL and `PipeListenerOptions` takes the result — and it is **read back
//! off the created pipe** by a test, because applying a descriptor and believing
//! it was applied is exactly the failure this is guarding against.
//!
//! That another *account* cannot open the pipe remains a claim about two
//! accounts, which no test in one process can make. `VERIFICATION.md` is where it
//! is checked.
//!
//! **Reading a pipe's descriptor costs a connection.** It is done by opening the
//! pipe's path, and opening a pipe's path takes one of its instances — a second
//! read of the same name comes back `ERROR_PIPE_BUSY`. So it is a thing tests do
//! to pipes of their own, and never a thing the daemon does to the channel it is
//! serving on: a health check that read the descriptor would eat the connection
//! somebody was about to make.
//!
//! # One line each way, and why not `read_to_end`
//!
//! The first version had each side read to end of stream. The server waited for
//! the client to close its write half; the client waited for the server's answer.
//! Neither ever moved, and `peerfectly status` simply hung with no output at all.
//!
//! So the framing is a single line each way. Neither side has to close anything
//! for the other to proceed, and the exchange is one request and one reply on one
//! connection — which is all this protocol has ever needed.
//!
//! [`ask`] and [`answer`] are here rather than in the binaries so the daemon, the
//! command line and the test all use the same two functions. The deadlock existed
//! because the two ends were written separately and only the pieces were tested.

use std::io;

use interprocess::os::windows::named_pipe::PipeListenerOptions;
use interprocess::os::windows::named_pipe::pipe_mode;
use interprocess::os::windows::named_pipe::tokio::DuplexPipeStream;

use daemon::limits;

/// The pipe's name.
///
/// Derived from the product name like every other machine-wide identifier, so
/// §13.3 stays one edit.
#[must_use]
pub fn name() -> String {
    format!(r"\\.\pipe\{}", limits::PRODUCT)
}

/// Who may use the control channel, and from what integrity.
///
/// ```text
/// D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)S:(ML;;NW;;;LW)
///   │ └─ the system  └─ admins  └─ anybody    └─ and nothing
///   │                             logged in      below Low
///   └─ and nothing inherited from wherever pipes live
/// ```
///
/// **`P` matters.** Without it the channel inherits whatever the pipe namespace
/// carries, and what this grants would be a floor rather than the whole of it.
///
/// `IU` is *Interactive Users* — anybody logged in at this machine, which is who
/// the command line runs as. They get read and write and **not** `GA`: creating
/// another instance of a named pipe is one of the rights `GA` carries, and a
/// client able to do that could take the next connection meant for the daemon.
///
/// `S:(ML;;NW;;;LW)` is the half that a DACL cannot say. The daemon runs as the
/// system, so the pipe would otherwise carry the system's own integrity and no
/// ordinary process could write to it whatever the DACL said. `LW` is the low
/// label and `NW` is no-write-up, which together mean: anything at low integrity
/// or above may write, which is everything a person runs.
///
/// A browser is not in that list and cannot be: this is not a port. See the
/// module's note on §7.3.
pub const WHO_MAY_USE_IT: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)S:(ML;;NW;;;LW)";

/// Listens for command-line clients.
///
/// # Errors
///
/// When the pipe cannot be created — most often because a daemon is already
/// running, which is the useful thing to learn.
pub fn listen() -> io::Result<Listener> {
    listen_at(&name())
}

/// What [`listen`] returns.
pub type Listener =
    interprocess::os::windows::named_pipe::tokio::PipeListener<pipe_mode::Bytes, pipe_mode::Bytes>;

/// One accepted connection.
pub type Stream = DuplexPipeStream<pipe_mode::Bytes>;

/// Listens on a given pipe name, carrying [`WHO_MAY_USE_IT`].
///
/// Separate from [`listen`] so a test can use a name of its own rather than
/// colliding with a daemon that may be running on the same machine — **and it
/// carries the same descriptor**, because a test that exercised the exchange
/// over a pipe anybody could open would be testing a channel the product does
/// not have.
///
/// # Errors
///
/// When the pipe cannot be created, or the descriptor will not parse.
pub fn listen_at(path: &str) -> io::Result<Listener> {
    listen_carrying(path, WHO_MAY_USE_IT)
}

/// The same, with the access control named.
///
/// Named rather than fixed so that a test can create a channel with a descriptor
/// it chose and read back what Windows made of it.
///
/// # Errors
///
/// When the descriptor will not parse, or the pipe cannot be created.
pub fn listen_carrying(path: &str, sddl: &str) -> io::Result<Listener> {
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;

    let wanted = widestring::U16CString::from_str(sddl).map_err(io::Error::other)?;
    let descriptor = SecurityDescriptor::deserialize(&wanted)?;

    let path = std::ffi::OsString::from(path);
    let mut options = PipeListenerOptions::new().path(path.as_os_str());
    options.security_descriptor = Some(descriptor);
    options.create_tokio_duplex::<pipe_mode::Bytes>()
}

/// Connects to a given pipe name, and establishes what answered **before
/// anything is sent**.
///
/// Two things happen here that did not before, and both are about the far end
/// being whatever holds a name rather than whatever we meant:
///
/// * The connection is made asking for identification and nothing more, so the
///   process on the other side can learn who is calling and cannot act as them.
/// * What answered is checked against who may be the daemon, and a refusal
///   happens with the request still in this process.
///
/// See [`super::who`] for both, including why a process id is a bar and not a
/// proof.
///
/// # Errors
///
/// When nothing is listening there, or what is listening is not the daemon.
pub async fn connect_at(path: &str) -> io::Result<Stream> {
    let stream = super::who::connect_identifying(path).await?;
    // **Not `PermissionDenied`.** That kind already means something here: the
    // client could not open the channel because the daemon is elevated and this
    // is not, and the command line translates it into those words. A refusal
    // that arrives after a successful connection wearing the same kind gets that
    // translation put over the top of it — which is how a precise reason became
    // a wrong guess, and cost an afternoon on a machine.
    super::who::answered_the_daemon(&stream).map_err(io::Error::other)?;
    Ok(stream)
}

/// Sends a request and reads the reply: the portable framing, over the pipe.
///
/// # Errors
///
/// When the pipe fails, or the reply is not what was expected.
pub async fn ask<Q, A>(stream: &mut Stream, request: &Q) -> io::Result<A>
where
    Q: serde::Serialize,
    A: serde::de::DeserializeOwned,
{
    daemon::control::framing::ask(stream, request).await
}

/// Reads one request: the portable framing, bounded as it is there.
///
/// # Errors
///
/// When the pipe fails, nothing is sent, or what is sent is not a request.
pub async fn read_request<Q: serde::de::DeserializeOwned>(stream: &mut Stream) -> io::Result<Q> {
    daemon::control::framing::read_request(stream).await
}

/// The same, given up on if nothing arrives.
///
/// # Errors
///
/// When the pipe fails, nothing is sent in time, or what is sent is not a
/// request or is larger than the protocol carries.
pub async fn read_request_in_time<Q: serde::de::DeserializeOwned>(
    stream: &mut Stream,
) -> io::Result<Q> {
    daemon::control::framing::read_request_in_time(stream).await
}

/// Writes one answer.
///
/// # Errors
///
/// When the pipe fails or the answer will not serialise.
pub async fn write_answer<A: serde::Serialize>(stream: &mut Stream, answer: &A) -> io::Result<()> {
    daemon::control::framing::write_answer(stream, answer).await
}

/// Reads a request and writes the reply the handler produces.
///
/// The two halves together, for a server with nothing to decide in between.
///
/// # Errors
///
/// When the pipe fails or the request is not readable.
pub async fn answer<Q, A, F, Fut>(stream: &mut Stream, handle: F) -> io::Result<()>
where
    Q: serde::de::DeserializeOwned,
    A: serde::Serialize,
    F: FnOnce(Q) -> Fut,
    Fut: core::future::Future<Output = A>,
{
    let asked: Q = read_request(stream).await?;
    let outcome = handle(asked).await;
    write_answer(stream, &outcome).await
}

/// Connects to a running daemon.
///
/// # Errors
///
/// When no daemon is listening.
pub async fn connect() -> io::Result<Stream> {
    connect_at(&name()).await
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    #[test]
    fn the_pipe_is_named_after_the_product() {
        let name = name();
        assert!(name.starts_with(r"\\.\pipe\"), "{name}");
        assert!(name.contains(limits::PRODUCT), "{name}");
    }

    /// Not a port. The reason is recorded here because "why not TCP" is exactly
    /// the question somebody asks when adding the web UI.
    #[test]
    fn the_control_channel_is_not_a_local_port() {
        let code = crate::code_of(include_str!("pipe.rs"));
        for forbidden in ["TcpListener", "127.0.0.1", "SocketAddr", "bind("] {
            assert!(!code.contains(forbidden), "`{forbidden}` would be reachable from a browser");
        }
    }

    /// **The descriptor is read back off the pipe Windows actually made.**
    ///
    /// The whole reason this is written down rather than defaulted is that the
    /// default was wrong in a way nothing reported: the DACL granted the person
    /// asking and the integrity label refused them anyway. A test that asserted
    /// the string this module passes in would have said the same thing before and
    /// after that bug.
    ///
    /// So what is asserted is what came back, and it is asserted through
    /// [`super::writable::who_else_can_write`] — the same decision the daemon
    /// makes about its own directory, which is how the two stay one answer.
    #[tokio::test]
    async fn the_channel_carries_what_it_was_given() {
        let path = format!(r"\\.\pipe\peerfectly-test-acl-{}", std::process::id());
        let _listening = listen_at(&path).expect("listens");

        let carried = super::super::protected::describe_including(
            std::path::Path::new(&path),
            super::super::protected::WHAT_THE_CHANNEL_CARRIES,
        )
        .expect("the channel says what protects it");

        assert!(
            carried.contains("D:P"),
            "the access control is the whole of it, not a floor over what pipes inherit: {carried}"
        );
        assert_eq!(
            vec!["IU".to_owned()],
            super::super::writable::who_else_can_write(&carried),
            "besides the system and administrators, exactly the people logged in: {carried}"
        );
        assert!(
            carried.contains("(ML;;NW;;;LW)"),
            "and low enough that an ordinary console may write to it: {carried}"
        );
    }

    /// The two halves of the descriptor are both there to be read — **and asking
    /// for one of them is not asking for the other**.
    ///
    /// Asking for the DACL alone renders a descriptor with no label in it, which
    /// reads exactly like a channel that has none. A channel with no label is the
    /// one a service creates at the system's own integrity and nobody can reach,
    /// which is the bug the explicit descriptor replaced — so a reader that asked
    /// for half would report the bug and the fix as the same string.
    ///
    /// **Two pipes, not one, and that is not tidiness.** Reading a pipe's
    /// descriptor opens its path, and opening a pipe's path takes an instance:
    /// the second read of the same name came back `ERROR_PIPE_BUSY`. Found here,
    /// and it is the reason the daemon never asks this of its own live channel.
    #[tokio::test]
    async fn asking_for_half_the_descriptor_sees_half_of_it() {
        let path = format!(r"\\.\pipe\peerfectly-test-half-{}", std::process::id());
        let _listening = listen_at(&path).expect("listens");
        let other = path.replace("half", "whole");
        let _also = listen_at(&other).expect("listens");
        let here = std::path::Path::new(&path);
        let there = std::path::Path::new(&other);

        let half = super::super::protected::describe(here).expect("reads the access control");
        assert!(!half.contains("(ML;"), "the label is not in it: {half}");

        let whole = super::super::protected::describe_including(
            there,
            super::super::protected::WHAT_THE_CHANNEL_CARRIES,
        )
        .expect("reads both");
        assert!(whole.contains("(ML;"), "and asking for both is what finds it: {whole}");
    }

    /// **Nothing is sent before it is known what answered.**
    ///
    /// The requirement is not that an impostor is detected — it is that it is
    /// detected *with the request still in this process*. A client that asked
    /// first and checked afterwards would have handed a network label, a peer
    /// name or an admission to whatever holds the channel's name.
    ///
    /// Asserted on the code, because a test that watched an impostor receive
    /// nothing would need a second account to run the impostor as.
    #[test]
    fn nothing_goes_out_before_the_far_end_is_established() {
        let code = crate::code_of(include_str!("pipe.rs"));
        let connecting = code
            .split("pub async fn connect_at")
            .nth(1)
            .and_then(|rest| rest.split("pub async fn").next())
            .expect("it is declared");

        for sending in ["write_all", "ask(", "serde_json::to_vec"] {
            assert!(
                !connecting.contains(sending),
                "`{sending}` while connecting would send before anything is known"
            );
        }
        assert!(
            connecting.contains("answered_the_daemon"),
            "and what answered is what is established"
        );
        // **The two refusals must not wear the same kind.** `PermissionDenied`
        // is translated by the command line into *"the daemon is elevated"*, so
        // an impostor refusal carrying it comes out as a guess instead of the
        // reason it already knows. That happened, and this is what it left.
        assert!(
            !connecting.contains("ErrorKind::PermissionDenied"),
            "a refusal that explains itself must not be given a kind that gets explained over"
        );

        let opened = connecting.find("connect_identifying").expect("it connects");
        let checked = connecting.find("answered_the_daemon").expect("it checks");
        assert!(opened < checked, "in that order, because there is nothing to check before");
    }

    /// Connecting with nothing listening says so, rather than hanging.
    #[tokio::test]
    async fn connecting_to_a_daemon_that_is_not_running_fails() {
        // A test machine may legitimately be running the daemon; the point is
        // that the call returns either way rather than waiting forever.
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), connect()).await;
        assert!(outcome.is_ok(), "connecting must not hang when nothing is listening");
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod round_trip {
    use daemon::control::{Command, Outcome};

    use super::*;

    /// A whole exchange over a real pipe, through the same two functions the
    /// daemon and the command line use.
    ///
    /// This is the test that was missing. Both ends were written separately, each
    /// half looked right, and together they deadlocked: the server read to end of
    /// stream waiting for the client to close, the client read to end of stream
    /// waiting for the server. `peerfectly status` hung with no output.
    ///
    /// Testing the pieces did not catch it, and could not have. Only running the
    /// two ends against each other does.
    #[tokio::test]
    async fn a_command_goes_out_and_an_answer_comes_back() {
        let path = format!(r"\\.\pipe\peerfectly-test-{}", std::process::id());
        let listener = listen_at(&path).expect("listens");

        let serving = tokio::spawn(async move {
            let mut stream = listener.accept().await.expect("accepts");
            answer(&mut stream, |command: Command| async move {
                assert_eq!(command, Command::Status, "the command arrived intact");
                Outcome::Done
            })
            .await
            .expect("answers");
        });

        let mut client = connect_at(&path).await.expect("connects");
        let outcome: Outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            ask(&mut client, &Command::Status),
        )
        .await
        .expect("the exchange must not hang")
        .expect("answers");

        assert_eq!(outcome, Outcome::Done);
        serving.await.expect("the server finished");
    }

    /// A second command on a second connection works too, so the daemon answers
    /// more than once.
    #[tokio::test]
    async fn the_daemon_answers_more_than_one_client() {
        let path = format!(r"\\.\pipe\peerfectly-test-many-{}", std::process::id());
        let listener = listen_at(&path).expect("listens");

        let serving = tokio::spawn(async move {
            for _ in 0..2 {
                let mut stream = listener.accept().await.expect("accepts");
                let _answered = answer(&mut stream, |_: Command| async { Outcome::Done }).await;
            }
        });

        for _ in 0..2 {
            let mut client = connect_at(&path).await.expect("connects");
            let outcome: Outcome = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                ask(&mut client, &Command::Status),
            )
            .await
            .expect("must not hang")
            .expect("answers");
            assert_eq!(outcome, Outcome::Done);
        }
        serving.await.expect("the server finished");
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod bounded {
    use daemon::control::{Command, Outcome};

    use super::*;

    /// The daemon's serving loop, in the shape the daemon has it: accept, and
    /// hand the connection to a task of its own.
    ///
    /// Written here rather than reached into `peerfectlyd.rs`, which is a binary. What
    /// holds the two together is `serving::each_connection_is_its_own_task`,
    /// which asserts the daemon's loop has this shape.
    fn serving_like_the_daemon(listener: Listener) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let Ok(mut stream) = listener.accept().await else { continue };
                tokio::spawn(async move {
                    let Ok(asked) = read_request_in_time::<Command>(&mut stream).await else {
                        return;
                    };
                    assert_eq!(Command::Status, asked);
                    let _sent = write_answer(&mut stream, &Outcome::Done).await;
                });
            }
        })
    }

    /// **A client that connects and says nothing blocks nobody.**
    ///
    /// The whole of what it takes to deny this service used to be: open a pipe,
    /// and stop. One connection answered at a time meant one client could hold
    /// the queue for as long as it cared to, with no privilege and nothing sent.
    #[tokio::test]
    async fn a_silent_client_does_not_stop_the_next_one() {
        let path = format!(r"\\.\pipe\peerfectly-test-silent-{}", std::process::id());
        let serving = serving_like_the_daemon(listen_at(&path).expect("listens"));

        // One connects and says nothing at all. Held open for the whole test.
        let _mute = connect_at(&path).await.expect("connects");

        // Another asks, and is answered while the first is still sitting there.
        let mut asking = connect_at(&path).await.expect("connects");
        let answered: Outcome = tokio::time::timeout(
            core::time::Duration::from_secs(5),
            ask(&mut asking, &Command::Status),
        )
        .await
        .expect("the silent one must not hold up this one")
        .expect("answers");

        assert_eq!(Outcome::Done, answered);
        serving.abort();
    }

    /// **A request past the bound is refused, and what is past it is not read.**
    ///
    /// The bound is `limits::MAX_CONTROL_REQUEST` and it is the protocol's rather
    /// than this platform's, so the next daemon inherits it instead of choosing
    /// its own.
    #[tokio::test]
    async fn an_oversized_request_is_refused() {
        use tokio::io::AsyncWriteExt as _;

        let path = format!(r"\\.\pipe\peerfectly-test-huge-{}", std::process::id());
        let listener = listen_at(&path).expect("listens");

        let reading = tokio::spawn(async move {
            let mut stream = listener.accept().await.expect("accepts");
            read_request::<Command>(&mut stream).await
        });

        let mut shouting = connect_at(&path).await.expect("connects");
        // No newline anywhere in it: a line that never ends.
        let too_much = vec![b'x'; usize::try_from(limits::MAX_CONTROL_REQUEST).unwrap() + 4_096];
        let _wrote = shouting.write_all(&too_much).await;
        let _flushed = shouting.flush().await;

        let refused = tokio::time::timeout(core::time::Duration::from_secs(5), reading)
            .await
            .expect("it must not sit there reading")
            .expect("the task finished")
            .expect_err("that is not a request this protocol carries");

        assert_eq!(std::io::ErrorKind::InvalidData, refused.kind(), "{refused}");
        assert!(
            refused.to_string().contains(&limits::MAX_CONTROL_REQUEST.to_string()),
            "and it says what the bound is: {refused}"
        );
    }

    /// **The wait is short, and it is the shared one.**
    ///
    /// Found by removing the rule: replacing `SAYS_SOMETHING_WITHIN` with a day
    /// broke nothing. The test below pauses time and advances to whatever timer
    /// it finds, so it proves *a* wait ends and says nothing about how long it
    /// is — and a wait long enough to be useless looks identical to it.
    ///
    /// So the bound itself is asserted, and asserted as the shared constant: a
    /// number written here would be a second bound, in the one place nobody
    /// reading `limits` would think to look.
    #[test]
    fn the_wait_is_short_and_is_the_one_everybody_uses() {
        assert!(
            limits::SAYS_SOMETHING_WITHIN <= core::time::Duration::from_secs(60),
            "a minute is already generous for a program that writes on connecting: {:?}",
            limits::SAYS_SOMETHING_WITHIN
        );
        assert!(
            limits::SAYS_SOMETHING_WITHIN >= core::time::Duration::from_secs(1),
            "and not so short that a loaded machine drops its own command line"
        );

        // The pipe hands the wait to the portable framing, which is where it is.
        let pipe = crate::code_of(include_str!("pipe.rs"));
        let delegating = pipe
            .split("pub async fn read_request_in_time")
            .nth(1)
            .and_then(|rest| rest.split("pub ").next())
            .expect("it is declared");
        assert!(
            delegating.contains("daemon::control::framing::read_request_in_time"),
            "the pipe waits the portable way: {delegating}"
        );

        let code = crate::code_of(include_str!("../../../daemon/src/control/framing.rs"));
        let waiting = code
            .split("pub async fn read_request_in_time")
            .nth(1)
            .and_then(|rest| rest.split("pub ").next())
            .expect("it is declared");

        assert!(waiting.contains("limits::SAYS_SOMETHING_WITHIN"), "the shared one: {waiting}");
        assert!(
            !waiting.contains("from_secs(") && !waiting.contains("from_millis("),
            "a duration written here is a bound nobody reading `limits` would find: {waiting}"
        );
    }

    /// **A client that says nothing is dropped, and the daemon is unaffected.**
    ///
    /// Time is paused, so this costs nothing to run: what is asserted is that the
    /// wait ends, not how long anybody sat through it.
    #[tokio::test(start_paused = true)]
    async fn a_client_that_says_nothing_is_dropped() {
        let path = format!(r"\\.\pipe\peerfectly-test-mute-{}", std::process::id());
        let listener = listen_at(&path).expect("listens");

        let waiting = tokio::spawn(async move {
            let mut stream = listener.accept().await.expect("accepts");
            read_request_in_time::<Command>(&mut stream).await
        });

        let _mute = connect_at(&path).await.expect("connects");

        let dropped = waiting.await.expect("the task finished").expect_err("nothing was said");
        assert_eq!(std::io::ErrorKind::TimedOut, dropped.kind(), "{dropped}");
        assert!(dropped.to_string().contains("said nothing"), "in words: {dropped}");
    }
}

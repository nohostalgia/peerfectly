//! Who is at each end of the control channel.
//!
//! Both ends ask, and they ask different questions.
//!
//! The **client** asks what process answered, because a client that speaks to
//! whatever holds a name is a client that can be answered by whatever took the
//! name first. It also asks for less than it is offered: connecting to a named
//! pipe hands the server the ability to *act as the person connecting* unless the
//! client says otherwise, and what `peerfectly status` needs from the daemon is an
//! answer, not an agent.
//!
//! The **daemon** asks who called, from the channel and never from what was sent.
//! A client that says who it is, is a client saying who it would like to be.
//!
//! # Why this is `unsafe`
//!
//! There is no safe wrapper for any of it. `interprocess` gives the process id at
//! each end and stops there; reading the account a process runs as, impersonating
//! a pipe client, and asking a token whether it really holds administrators are
//! all direct calls. Every one of them is a read: nothing here changes any
//! object's security, and the one thing that changes this *thread's* is undone by
//! a guard before the function returns.
//!
//! # What the process id can and cannot say
//!
//! **A process id is a bar, not a proof.** Windows reuses them, so an id that
//! names the daemon now named something else a moment ago, and a client that
//! checked one could in principle be checking a process that has since gone. The
//! guarantee this rests on is the *name*: the service starts with the machine,
//! before any session, so taking the channel's name first would require code
//! running earlier still, which is already privileged. The check below raises the
//! cost of the remaining case and is written down as exactly that.

#![cfg(windows)]
#![allow(
    unsafe_code,
    reason = "reading who is at each end of a pipe has no safe wrapper; see the module docs"
)]

use std::io;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, RevertToSelf, TOKEN_ELEVATION_TYPE, TOKEN_QUERY, TOKEN_USER,
    TokenElevationType, TokenElevationTypeLimited, TokenUser, WinBuiltinAdministratorsSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{ImpersonateNamedPipeClient, WaitNamedPipeW};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use daemon::control::Caller;

use super::pipe::Stream;

/// The administrators of this machine, as a token renders them.
///
/// Accepted as an owner because only an administrator can set it: a process that
/// does not hold the group cannot make an object owned by it.
pub const ADMINISTRATORS: &str = "S-1-5-32-544";

/// The account a service running as the machine has.
///
/// Written out rather than abbreviated: this is compared against what
/// [`who_runs`] renders, and what it renders is the SID.
pub const THE_SYSTEM: &str = "S-1-5-18";

/// What went wrong asking, in words a person can act on.
pub type Refusal = String;

/// A handle the platform gave us, closed when it goes.
struct Held(HANDLE);

impl Drop for Held {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: ours since the call that produced it, closed exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Impersonation, undone when it goes.
///
/// **The guard is the point.** A thread left impersonating a client would carry
/// that client's account into whatever it did next, which for this daemon is
/// every other network on the machine.
struct Wearing;

impl Drop for Wearing {
    fn drop(&mut self) {
        // SAFETY: undoes an impersonation this thread began. Harmless if it did
        // not, which cannot happen: this exists only where one did.
        unsafe { RevertToSelf() };
    }
}

/// Connects to the channel **without handing over the ability to act as us**.
///
/// A named pipe client gets `SecurityImpersonation` by default, which lets the
/// server borrow the caller's account and use it against anything on the machine
/// or the network. `SECURITY_IDENTIFICATION` gives the server enough to *know*
/// who is calling and nothing to act with, which is exactly the trade this
/// protocol wants: the daemon decides what a person may do, and never does
/// anything as them.
///
/// `FILE_FLAG_OVERLAPPED` is not optional — the stream this becomes is driven by
/// tokio, and tokio registers the handle with a completion port.
///
/// # Errors
///
/// When nothing is listening, when every instance is busy for longer than
/// [`WAITS_FOR`], or when the handle cannot be driven asynchronously.
pub async fn connect_identifying(path: &str) -> io::Result<Stream> {
    // **Off the runtime's threads.** Opening a pipe whose every instance is busy
    // means waiting, and the wait is a blocking call with no asynchronous form.
    // Left where it was, it stopped the very thread that was about to free an
    // instance: a test asked twice in a row and the second ask waited the whole
    // five seconds for a server that could not be polled to make the next one.
    let name = path.to_owned();
    let opened = tokio::task::spawn_blocking(move || open_identifying(&name))
        .await
        .map_err(io::Error::other)??;

    // Back on the runtime, because this is where tokio registers the handle with
    // its completion port.
    Stream::try_from(opened).map_err(|cause| io::Error::other(cause.to_string()))
}

/// Opens the channel, waiting if every instance is busy.
///
/// Blocking, and called as such. See [`connect_identifying`].
fn open_identifying(path: &str) -> io::Result<OwnedHandle> {
    let wide: Vec<u16> = path.encode_utf16().chain(core::iter::once(0)).collect();

    let handle = loop {
        // SAFETY: the name outlives the call; no security attributes and no
        // template. The handle that comes back is ours.
        let opened = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,
                core::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                core::ptr::null_mut(),
            )
        };
        if opened != INVALID_HANDLE_VALUE {
            break opened;
        }

        let why = io::Error::last_os_error();
        if why.raw_os_error() != Some(PIPE_BUSY) {
            return Err(why);
        }
        // Every instance is serving somebody else. Waiting is the whole of the
        // handling: the daemon makes the next instance as soon as it accepts.
        // SAFETY: the name outlives the call.
        let waited = unsafe { WaitNamedPipeW(wide.as_ptr(), WAITS_FOR) };
        if waited == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the daemon is answering other commands and did not free a connection",
            ));
        }
    };

    // SAFETY: opened just above, not closed, and given away exactly once.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
}

/// How long a client waits for a busy channel, in milliseconds.
const WAITS_FOR: u32 = 5_000;

/// `ERROR_PIPE_BUSY`.
const PIPE_BUSY: i32 = 231;

/// Whether what answered on the channel is the daemon, given both accounts.
///
/// Pure, and both identities are handed in, so the decision is tested rather
/// than inferred from whatever this machine happens to be running.
///
/// Two answers are accepted and they are not the same strength:
///
/// * **The system.** What the service runs as. This is the real bar: a process
///   running as the system was started by the machine, and to have taken the
///   channel's name before it, something would have had to be running earlier
///   still — which is already privileged.
/// * **The same account as the person asking.** What a daemon run in the
///   foreground runs as. Deliberately weaker, and it has to be: a foreground
///   daemon is somebody's own elevated console, and refusing it would mean the
///   command line only worked against the service, which is the debugging path
///   gone. What it still refuses is **somebody else** holding the name, which is
///   the case that is an attack rather than a workflow.
///
/// # Errors
///
/// Naming what answered, so that a person can go and look at it.
pub fn answered_by_the_daemon(answered: &str, asking: &str) -> Result<(), Refusal> {
    if answered == THE_SYSTEM || answered == ADMINISTRATORS || answered == asking {
        return Ok(());
    }
    Err(format!(
        "something else is holding the control channel: it belongs to {answered}, and the \
         daemon's belongs to the system. Nothing was sent."
    ))
}

/// The same, asked of a connection.
///
/// **A process id is a bar and not a proof.** Windows reuses them: the id this
/// reads named something else a moment ago and could name something else a
/// moment from now, so what this establishes is that at the instant it looked,
/// the far end was the daemon. The guarantee underneath is the *name* — the
/// service takes it at boot, before any session — and this raises the cost of
/// the case the name does not cover rather than closing it.
///
/// # Errors
///
/// When either end cannot be identified, or the far end is not the daemon. Never
/// answered by guessing: a client that could not tell what answered must not send
/// a command to it.
pub fn answered_the_daemon(stream: &Stream) -> Result<(), Refusal> {
    let answered = owner_of(stream)?;
    let asking = who_runs(std::process::id())?;
    answered_by_the_daemon(&answered, &asking)
}

/// Who owns the channel, read off the handle this client already holds.
///
/// **A property of the object, not of a number.** Reading the *process* at the
/// far end meant opening its token — which an ordinary account may not do to a
/// process running as the system, so the check refused every unelevated command
/// on a machine where everything was working. Found on a machine; no test in one
/// process could see it, because there both ends are the same account.
///
/// It is also the stronger question. A process id is reused and names whatever
/// holds it now; an owner is stamped on the object when it is created and cannot
/// be set to an account the creator does not hold.
///
/// Reading it is not writing: a client that may not connect may still read this,
/// which is what makes it usable for saying why.
///
/// # Errors
///
/// When the handle will not say, which is not an answer to guess at.
pub fn owner_of(stream: &Stream) -> Result<String, Refusal> {
    let mut owner: PSID = core::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
    // SAFETY: the stream owns the handle for the call; every pointer we do not
    // want is null, and the descriptor that comes back is ours to free.
    let read = unsafe {
        GetSecurityInfo(
            stream.as_raw_handle() as HANDLE,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    let held = Freed(descriptor);
    if read != 0 || owner.is_null() {
        return Err(format!("the channel would not say who owns it: {read}"));
    }
    let rendered = rendered_sid(owner);
    drop(held);
    rendered
}

/// A descriptor the platform allocated, freed when it goes.
struct Freed(PSECURITY_DESCRIPTOR);

impl Drop for Freed {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocated by `GetSecurityInfo`, freed exactly once.
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.0.cast()) };
        }
    }
}

/// The account a process runs as, as a SID.
///
/// # Errors
///
/// When the process cannot be opened — which includes it having gone — or its
/// token will not answer.
pub fn who_runs(process: u32) -> Result<String, Refusal> {
    // SAFETY: asks for the least that answers the question. A null handle back
    // means it could not, and `Held` closes what did come back.
    let opened = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process) };
    if opened.is_null() {
        return Err(format!(
            "process {process} could not be asked what account it runs as: {}",
            io::Error::last_os_error()
        ));
    }
    let held = Held(opened);

    let mut token: HANDLE = core::ptr::null_mut();
    // SAFETY: `held` is open for the call; the token is ours from here.
    let got = unsafe { OpenProcessToken(held.0, TOKEN_QUERY, &raw mut token) };
    let token = Held(token);
    if got == 0 {
        return Err(format!(
            "process {process} would not say what account it runs as: {}",
            io::Error::last_os_error()
        ));
    }
    user_of(token.0)
}

/// Who is calling, read from the channel and from nothing else.
///
/// The thread wears the caller's account for exactly as long as it takes to read
/// it, and [`Wearing`] takes it off again on the way out of this function —
/// including on the way out through an error.
///
/// # Errors
///
/// When the client cannot be impersonated, or the token will not answer. Never
/// answered by guessing: a daemon that could not tell who was calling must not
/// decide as though nobody were.
pub fn the_caller(stream: &Stream) -> Result<Caller, Refusal> {
    // SAFETY: the stream owns the handle and outlives the call.
    let worn = unsafe { ImpersonateNamedPipeClient(stream.as_raw_handle() as HANDLE) };
    if worn == 0 {
        return Err(format!(
            "the channel would not say who is calling: {}",
            io::Error::last_os_error()
        ));
    }
    let _undone = Wearing;

    let mut token: HANDLE = core::ptr::null_mut();
    // SAFETY: this thread is impersonating, so it has a token to open. `1` is
    // `OpenAsSelf`: the token is opened with **this process's** rights rather
    // than the caller's, so a caller whose account may not open tokens does not
    // thereby become one this daemon cannot identify.
    let got = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) };
    let token = Held(token);
    if got == 0 {
        return Err(format!("the caller's token would not open: {}", io::Error::last_os_error()));
    }

    let name = user_of(token.0)?;
    let privileged = holds_administrators(token.0);
    Ok(Caller::Identified {
        name,
        privileged,
        could_be_privileged: !privileged && one_prompt_away(token.0),
    })
}

/// Whether a token is an administrator's with its group filtered out: the
/// unelevated half of a pair Windows made at logon, whose other half the
/// elevation prompt gives.
///
/// **For offering only.** It decides nothing: whatever this caller asks is
/// decided on this token, which is not privileged. A token that will not say is
/// not one prompt away.
fn one_prompt_away(token: HANDLE) -> bool {
    let mut kind: TOKEN_ELEVATION_TYPE = 0;
    let mut written = 0_u32;
    // SAFETY: the token is open for the call; the buffer is one
    // `TOKEN_ELEVATION_TYPE`, and its size is what we say it is.
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenElevationType,
            (&raw mut kind).cast(),
            core::mem::size_of::<TOKEN_ELEVATION_TYPE>() as u32,
            &raw mut written,
        )
    };
    read != 0 && kind == TokenElevationTypeLimited
}

/// Whether a token really holds administrators.
///
/// **Not whether the account is in the group.** An administrator running
/// unelevated carries the group as *deny-only*, and this answers no for them —
/// which is right: what this decides is whether somebody may act on the machine
/// right now, and an unelevated console is somebody who has not asked to.
///
/// A token that will not answer is not an administrator. The safe direction is
/// the refusing one, and there is no case where failing to decide should decide
/// in favour.
fn holds_administrators(token: HANDLE) -> bool {
    let mut administrators = [0_u8; SID_IS_AT_MOST];
    let mut length = SID_IS_AT_MOST as u32;
    // SAFETY: the buffer is ours and its length is what we say it is.
    let made = unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            core::ptr::null_mut(),
            administrators.as_mut_ptr().cast(),
            &raw mut length,
        )
    };
    if made == 0 {
        return false;
    }

    let mut holds = 0_i32;
    // SAFETY: the token is open for the call and the SID is the one just made.
    let asked =
        unsafe { CheckTokenMembership(token, administrators.as_mut_ptr().cast(), &raw mut holds) };
    asked != 0 && holds != 0
}

/// The largest a SID can be.
const SID_IS_AT_MOST: usize = 68;

/// The account a token belongs to, as a SID.
fn user_of(token: HANDLE) -> Result<String, Refusal> {
    let mut wanted = 0_u32;
    // SAFETY: asking for the size with no buffer, which is how this is done.
    unsafe { GetTokenInformation(token, TokenUser, core::ptr::null_mut(), 0, &raw mut wanted) };
    if wanted == 0 {
        return Err(format!(
            "a token would not say how big its user is: {}",
            io::Error::last_os_error()
        ));
    }

    let mut buffer = vec![0_u8; wanted as usize];
    // SAFETY: the buffer is `wanted` bytes, which is what was asked for.
    let read = unsafe {
        GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), wanted, &raw mut wanted)
    };
    if read == 0 {
        return Err(format!("a token would not say whose it is: {}", io::Error::last_os_error()));
    }

    // SAFETY: the platform wrote a `TOKEN_USER` at the front of the buffer, and
    // the SID it points at lives in the same allocation.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    rendered_sid(user.User.Sid)
}

/// A SID as the text everything here compares.
fn rendered_sid(sid: PSID) -> Result<String, Refusal> {
    let mut rendered: windows_sys::core::PWSTR = core::ptr::null_mut();
    // SAFETY: the SID is valid for the call; what comes back is ours to free.
    let ok = unsafe { ConvertSidToStringSidW(sid, &raw mut rendered) };
    if ok == 0 || rendered.is_null() {
        return Err(format!("an account would not render: {}", io::Error::last_os_error()));
    }

    // SAFETY: null-terminated by the call above.
    let mut length = 0;
    while unsafe { *rendered.add(length) } != 0 {
        length = length.saturating_add(1);
    }
    // SAFETY: `length` units were written before the terminator.
    let text = String::from_utf16_lossy(unsafe { core::slice::from_raw_parts(rendered, length) });
    // SAFETY: allocated by `ConvertSidToStringSidW`, freed exactly once.
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(rendered.cast());
    }
    Ok(text)
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// **One prompt away is never privileged already.** Asked of this test's own
    /// token, which is one of the three kinds whoever runs it has: elevated, an
    /// administrator's filtered one, or an ordinary person's.
    #[test]
    fn one_prompt_away_is_never_privileged_already() {
        let mut token: HANDLE = core::ptr::null_mut();
        // SAFETY: this process's own pseudo-handle, and an out parameter we own.
        let opened = unsafe {
            OpenProcessToken(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                TOKEN_QUERY,
                &raw mut token,
            )
        };
        assert_ne!(0, opened, "this process's token opens");
        let token = Held(token);

        let privileged = holds_administrators(token.0);
        let away = one_prompt_away(token.0);
        assert!(!(privileged && away), "an elevated token is not one prompt away");
    }

    /// The system is the daemon, whoever is asking.
    #[test]
    fn the_system_answering_is_the_daemon() {
        assert!(answered_by_the_daemon(THE_SYSTEM, "S-1-5-21-alice").is_ok());
        assert!(answered_by_the_daemon(THE_SYSTEM, "S-1-5-21-bob").is_ok());
    }

    /// **Somebody else holding the name is refused, and named.**
    ///
    /// *«Something is wrong»* leaves a person with nothing to do. What they can
    /// do with an account is go and find the process running as it.
    #[test]
    fn somebody_else_answering_is_refused_and_named() {
        let refused = answered_by_the_daemon("S-1-5-21-mallory", "S-1-5-21-alice")
            .expect_err("that is not the daemon");
        assert!(refused.contains("S-1-5-21-mallory"), "it says who: {refused}");
        assert!(refused.contains("Nothing was sent"), "and that nothing went out: {refused}");
    }

    /// A daemon in the foreground is the person's own, and answers them.
    ///
    /// The weaker of the two answers, and it has to be: refusing it would leave
    /// the command line working against the service alone, which is the
    /// debugging path gone. A process running as you is not a boundary you have.
    #[test]
    fn a_persons_own_daemon_answers_them() {
        assert!(answered_by_the_daemon("S-1-5-21-alice", "S-1-5-21-alice").is_ok());
        assert!(
            answered_by_the_daemon("S-1-5-21-alice", "S-1-5-21-bob").is_err(),
            "but not somebody else's"
        );
    }

    /// The decision is made of the two accounts and nothing else.
    ///
    /// Not of a process id, which is reused, and not of a path or a window title
    /// or anything else a squatter could arrange to match.
    #[test]
    fn what_answered_is_decided_from_accounts_alone() {
        let code = crate::code_of(include_str!("who.rs"));
        let deciding = code
            .split("pub fn answered_by_the_daemon")
            .nth(1)
            // `code_of` has already taken the comments out, so the next item is
            // what ends this one — not the doc comment introducing it.
            .and_then(|rest| rest.split("pub fn").next())
            .unwrap_or_default();

        for weaker in ["process", "current_exe", "path", "name()"] {
            assert!(!deciding.contains(weaker), "`{weaker}` is not who somebody is");
        }
    }

    /// **What answered is read off the channel's owner, not its process.**
    ///
    /// Found on a machine: reading the far process meant opening its token, and
    /// an ordinary account may not open the token of a process running as the
    /// system — so every unelevated command was refused on a machine where
    /// everything worked. No test in one process can see that, because there both
    /// ends are the same account, which is why this is asserted on the code.
    #[test]
    fn what_answered_comes_from_the_channel_rather_than_a_process() {
        let code = crate::code_of(include_str!("who.rs"));
        let establishing = code
            .split("pub fn answered_the_daemon")
            .nth(1)
            .and_then(|rest| rest.split("pub fn").next())
            .expect("it is declared");

        assert!(establishing.contains("owner_of(stream)"), "the object says: {establishing}");
        assert!(
            !establishing.contains("server_process_id"),
            "a process id is reused, and its token is not ours to open: {establishing}"
        );
    }

    /// An elevated daemon in the foreground owns its channel as an administrator.
    ///
    /// Accepted, because only an administrator can set it: a process that does
    /// not hold the group cannot make an object owned by it. Refusing it would
    /// leave the command line working against the service alone.
    #[test]
    fn an_administrators_channel_is_the_daemons() {
        assert!(answered_by_the_daemon(ADMINISTRATORS, "S-1-5-21-alice").is_ok());
        assert!(
            answered_by_the_daemon("S-1-5-21-mallory", "S-1-5-21-alice").is_err(),
            "but an ordinary account that is not yours is not"
        );
    }

    /// This process runs as somebody, and that somebody renders as a SID.
    #[test]
    fn a_process_says_what_account_it_runs_as() {
        let who = who_runs(std::process::id()).expect("this process answers about itself");
        assert!(who.starts_with("S-1-"), "an account is a SID: {who}");
        assert!(who.len() > "S-1-5-".len(), "and a whole one: {who}");
    }

    /// A process that is not there is said not to be, rather than answered for.
    #[test]
    fn a_process_that_is_not_there_is_not_guessed_at() {
        // Odd ids are never process ids on Windows: they are multiples of four.
        let answer = who_runs(u32::MAX - 1);
        assert!(answer.is_err(), "there is nobody to answer for: {answer:?}");
    }

    /// **The caller is read from the channel, and the channel is all of it.**
    ///
    /// A client that says who it is, is a client saying who it would like to be.
    /// Asserted on the code because the alternative — a test that sent a false
    /// name and saw it ignored — would only cover the one field somebody thought
    /// to fake.
    #[test]
    fn nothing_the_client_sends_reaches_the_answer() {
        let code = crate::code_of(include_str!("who.rs"));
        let deciding = code
            .split("pub fn the_caller")
            .nth(1)
            .and_then(|rest| rest.split("#[cfg(windows)]").next())
            .unwrap_or_default();

        for sent in ["Command", "serde", "request", "from_str", "read_line"] {
            assert!(
                !deciding.contains(sent),
                "`{sent}` in deciding who is calling would let the caller name themselves"
            );
        }
        assert!(
            deciding.contains("ImpersonateNamedPipeClient"),
            "the channel is what says who is there"
        );
    }

    /// The impersonation is taken off by a guard, not by remembering to.
    ///
    /// A thread left wearing a caller's account carries it into whatever it does
    /// next, and what this daemon does next is every other network on the
    /// machine. An early return is the case a written-out `RevertToSelf` misses.
    #[test]
    fn the_impersonation_comes_off_on_every_way_out() {
        let code = crate::code_of(include_str!("who.rs"));
        assert!(code.contains("impl Drop for Wearing"), "it is undone by going out of scope");
        assert_eq!(
            1,
            code.matches("RevertToSelf()").count(),
            "in one place, so there is no second path that forgets"
        );
        assert!(
            code.contains("let _undone = Wearing;"),
            "and the guard is held rather than dropped where it is made"
        );
    }

    /// Connecting asks for less than it is offered.
    #[test]
    fn connecting_hands_over_no_agency() {
        let code = crate::code_of(include_str!("who.rs"));
        assert!(code.contains("SECURITY_SQOS_PRESENT"), "the quality of service is stated");
        assert!(code.contains("SECURITY_IDENTIFICATION"), "and it is identification, not more");
        for handing_over in ["SECURITY_IMPERSONATION", "SECURITY_DELEGATION"] {
            assert!(!code.contains(handing_over), "`{handing_over}` would hand over an agent");
        }
    }

    /// The system's account is the one it is compared against.
    #[test]
    fn the_system_is_written_out_rather_than_abbreviated() {
        assert_eq!("S-1-5-18", THE_SYSTEM, "what a token renders as, not what SDDL abbreviates");
    }
}

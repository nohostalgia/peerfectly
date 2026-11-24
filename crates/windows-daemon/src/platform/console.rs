//! One line from the console, with echo off: a word of the founder's.
//!
//! **Only from the console.** Never from the program's arguments, which other
//! processes can read, nor from the environment. The console's mode is put back
//! when this returns, on an error too, so a person is never left typing into a
//! console that shows nothing.

#![cfg(windows)]
#![allow(
    unsafe_code,
    reason = "the console's mode is a Win32 API with no safe wrapper; the unsafe surface is \
              confined to this module, as `custody` and `route_table` confine theirs"
)]

use std::io::{BufRead as _, Write as _};

use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, GetConsoleMode, GetStdHandle,
    STD_INPUT_HANDLE, SetConsoleMode,
};
use zeroize::Zeroizing;

/// The console's input mode, put back when this goes.
struct Restore {
    handle: windows_sys::Win32::Foundation::HANDLE,
    mode: CONSOLE_MODE,
}

impl Drop for Restore {
    fn drop(&mut self) {
        // SAFETY: the handle is the process's own standard input, valid for the
        // process's lifetime, and the mode is the one read from it.
        let _ = unsafe { SetConsoleMode(self.handle, self.mode) };
    }
}

/// Turns the console's echo back on where it reads lines and shows nothing.
///
/// A console's mode belongs to the console, not to the process that set it: a
/// prompt killed while it hid what was typed — Ctrl+C at a word of the
/// founder's, in an earlier version — left every later answer, a `yes` or a
/// `no` included, unseen. Asked at every start, so such a console repairs
/// itself. Quiet where standard input is no console.
pub fn echo_back_on() {
    // SAFETY: a documented call with a documented constant; the handle it
    // returns is checked below before it is used.
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode: CONSOLE_MODE = 0;
    // SAFETY: `mode` is a valid, writable `CONSOLE_MODE` for the call's lifetime.
    if handle.is_null() || unsafe { GetConsoleMode(handle, &raw mut mode) } == 0 {
        return;
    }
    if mode & ENABLE_LINE_INPUT != 0 && mode & ENABLE_ECHO_INPUT == 0 {
        // SAFETY: the handle was checked to be a console above.
        let _ = unsafe { SetConsoleMode(handle, mode | ENABLE_ECHO_INPUT) };
    }
}

/// Asks for one line without showing what is typed.
///
/// # Errors
///
/// When standard input is not a console, or it cannot be read.
pub fn ask(prompt: &str) -> std::io::Result<Zeroizing<String>> {
    // SAFETY: a documented call with a documented constant; the handle it
    // returns is checked below before it is used.
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode: CONSOLE_MODE = 0;
    // SAFETY: `mode` is a valid, writable `CONSOLE_MODE` for the call's lifetime.
    if handle.is_null() || unsafe { GetConsoleMode(handle, &raw mut mode) } == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the founder's words are asked at a console, and there is none",
        ));
    }
    let restore = Restore { handle, mode };
    // SAFETY: the handle was checked to be a console above.
    if unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) } == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut out = std::io::stdout();
    write!(out, "{prompt}")?;
    out.flush()?;
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;
    drop(restore);
    // The newline the person typed was not echoed.
    writeln!(out)?;
    Ok(Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_owned()))
}

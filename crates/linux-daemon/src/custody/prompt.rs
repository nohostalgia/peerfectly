//! A passphrase, from the terminal, with echo off.
//!
//! **Only from the terminal.** Never from the program's arguments, which every
//! account on the machine can read in `/proc` and which the shell keeps in its
//! history; never from the environment, which is inherited by whatever the
//! process starts. `/dev/tty` is the controlling terminal, so a passphrase
//! cannot be piped in by mistake from a file either.

use std::io::{BufRead as _, Write as _};

use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
use zeroize::Zeroizing;

/// The terminal's settings, put back when this goes — on an error too, so a
/// person is never left typing into a terminal that shows nothing.
struct Restore<'a> {
    terminal: &'a std::fs::File,
    settings: rustix::termios::Termios,
}

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        let _ = tcsetattr(self.terminal, OptionalActions::Now, &self.settings);
    }
}

/// Asks for a passphrase.
///
/// # Errors
///
/// When there is no terminal to ask at, or it cannot be read.
pub fn ask(prompt: &str) -> std::io::Result<Zeroizing<String>> {
    let terminal =
        std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").map_err(|cause| {
            std::io::Error::new(
                cause.kind(),
                format!("a passphrase is asked on a terminal, and there is none: {cause}"),
            )
        })?;

    let settings = tcgetattr(&terminal)?;
    let restore = Restore { terminal: &terminal, settings: settings.clone() };
    let mut silent = settings;
    silent.local_modes.remove(LocalModes::ECHO);
    silent.local_modes.insert(LocalModes::ECHONL);
    tcsetattr(&terminal, OptionalActions::Now, &silent)?;

    let mut writer = &terminal;
    write!(writer, "{prompt}")?;
    writer.flush()?;

    let mut line = Zeroizing::new(String::new());
    std::io::BufReader::new(&terminal).read_line(&mut line)?;
    drop(restore);

    let trimmed = Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_owned());
    Ok(trimmed)
}

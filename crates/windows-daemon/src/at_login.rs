//! The tray at login: a value under the person's own `Run` key.
//!
//! Written by the tray's first start, switched off and on from its menu, and
//! **never written again once removed**: a person who switched it off is not
//! overruled by the next start. A flag under the person's own key records that
//! it was offered once. While the entry exists, it is pointed at the running
//! tray, `peerfectly-tray.exe`, so it follows the program if it moves — and an entry
//! written when the tray was `peerfectly.exe tray` moves to the tray program the
//! first time that starts.
//!
//! Per person, under `HKEY_CURRENT_USER`: nothing here needs elevation, and one
//! person's choice is not another's.

#![cfg(windows)]

use std::path::Path;

use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};

/// Where Windows reads what to start at login, for this person.
pub const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// This product's own key, for this person.
pub const OURS: &str = r"Software\peerfectly";

/// The value's name under [`RUN`].
const VALUE: &str = "peerfectly";

/// The flag under [`OURS`] saying the entry was offered once.
const OFFERED: &str = "tray at login offered";

/// A person's login entry for the tray.
#[derive(Debug, Clone)]
pub struct AtLogin {
    /// The `Run` key.
    run: String,
    /// This product's key.
    ours: String,
}

impl AtLogin {
    /// The person running this.
    #[must_use]
    pub fn for_this_person() -> Self {
        Self { run: RUN.to_owned(), ours: OURS.to_owned() }
    }

    /// Both keys under a scratch key of this person's, for tests.
    #[must_use]
    pub fn under(scratch: &str) -> Self {
        Self { run: format!(r"{scratch}\Run"), ours: format!(r"{scratch}\peerfectly") }
    }

    /// What the entry runs: the tray program, which needs no argument.
    #[must_use]
    pub fn command_for(program: &Path) -> String {
        format!("\"{}\"", program.display())
    }

    /// What the entry says, if there is one.
    #[must_use]
    pub fn entry(&self) -> Option<String> {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(&self.run, KEY_READ)
            .and_then(|key| key.get_value::<String, _>(VALUE))
            .ok()
    }

    /// Whether the tray starts at login.
    #[must_use]
    pub fn is_on(&self) -> bool {
        self.entry().is_some()
    }

    /// At the tray's start: the entry is written the first time, pointed at
    /// `program` while it exists, and left alone once removed. Returns whether it
    /// is on.
    ///
    /// # Errors
    ///
    /// When the registry refuses.
    pub fn on_start(&self, program: &Path) -> std::io::Result<bool> {
        if self.is_on() {
            self.write(program)?;
            return Ok(true);
        }
        if self.offered() {
            return Ok(false);
        }
        self.set(true, program)?;
        Ok(true)
    }

    /// Switches it on or off, as the person asked.
    ///
    /// # Errors
    ///
    /// When the registry refuses.
    pub fn set(&self, on: bool, program: &Path) -> std::io::Result<()> {
        if on {
            self.write(program)?;
        } else if let Ok(key) =
            RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(&self.run, KEY_WRITE)
        {
            match key.delete_value(VALUE) {
                Err(cause) if cause.kind() != std::io::ErrorKind::NotFound => return Err(cause),
                _ => {}
            }
        }
        let (ours, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(&self.ours)?;
        ours.set_value(OFFERED, &1_u32)
    }

    /// Writes the entry for `program`.
    fn write(&self, program: &Path) -> std::io::Result<()> {
        let (run, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(&self.run)?;
        run.set_value(VALUE, &Self::command_for(program))
    }

    /// Whether it was offered before.
    fn offered(&self) -> bool {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(&self.ours, KEY_READ)
            .and_then(|key| key.get_value::<u32, _>(OFFERED))
            .is_ok_and(|flag| flag == 1)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use std::path::Path;

    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    use super::AtLogin;

    /// A scratch key of this person's, removed when dropped.
    struct Scratch(String);

    impl Scratch {
        fn new(name: &str) -> Self {
            Self(format!(r"Software\peerfectly-test-{name}-{}", std::process::id()))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.0);
        }
    }

    /// **Written on the first start, and never again once removed.**
    #[test]
    fn a_removed_entry_is_not_written_back() {
        let scratch = Scratch::new("removed");
        let login = AtLogin::under(&scratch.0);
        let program = Path::new(r"C:\Program Files\peerfectly\peerfectly-tray.exe");

        assert!(login.on_start(program).unwrap(), "the first start writes it");
        assert_eq!(Some(AtLogin::command_for(program)), login.entry());

        login.set(false, program).unwrap();
        assert!(!login.on_start(program).unwrap(), "a later start leaves it removed");
        assert!(login.entry().is_none());

        login.set(true, program).unwrap();
        assert!(login.is_on(), "and the person can switch it back on");
    }

    /// While it exists it points at the running program, so it follows a move.
    #[test]
    fn the_entry_follows_the_program() {
        let scratch = Scratch::new("moved");
        let login = AtLogin::under(&scratch.0);

        login.on_start(Path::new(r"C:\old\peerfectly-tray.exe")).unwrap();
        login.on_start(Path::new(r"C:\new\peerfectly-tray.exe")).unwrap();

        assert_eq!(Some(r#""C:\new\peerfectly-tray.exe""#.to_owned()), login.entry());
    }

    /// **An entry from when the tray was `peerfectly.exe tray` moves over by
    /// itself**, the first time the tray program starts: nobody has to switch it
    /// off and on again.
    #[test]
    fn an_entry_for_the_old_tray_moves_to_the_tray_program() {
        let scratch = Scratch::new("old-tray");
        let login = AtLogin::under(&scratch.0);
        let (run, _) =
            RegKey::predef(HKEY_CURRENT_USER).create_subkey(format!(r"{}\Run", scratch.0)).unwrap();
        run.set_value("peerfectly", &r#""C:\Program Files\peerfectly\peerfectly.exe" tray"#)
            .unwrap();

        assert!(
            login.on_start(Path::new(r"C:\Program Files\peerfectly\peerfectly-tray.exe")).unwrap()
        );
        assert_eq!(
            Some(r#""C:\Program Files\peerfectly\peerfectly-tray.exe""#.to_owned()),
            login.entry()
        );
    }
}

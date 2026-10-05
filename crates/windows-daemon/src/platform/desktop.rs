//! Three things the tray asks of the person's desktop: dark menus, the
//! elevation prompt, and a message window.
//!
//! # Dark menus: tried, never required
//!
//! `muda`'s theme covers menu bars only, not context menus. Windows gives dark
//! context menus to a process that opts in through `SetPreferredAppMode`, an
//! **undocumented** export of `uxtheme.dll` with no name, only ordinal 135,
//! present since Windows 10 1903; `FlushMenuThemes`, ordinal 136, applies it.
//! Both are looked up at run time, and when either is missing the menus are
//! light and nothing else changes. Nothing depends on it.
//!
//! # Stopping goes through a fresh, elevated `peerfectly stop`
//!
//! The tray is not elevated and must not be. Stopping the service is the
//! machine's act, so the tray runs `peerfectly stop` through `ShellExecuteW` with the
//! `runas` verb: Windows shows its prompt, the elevated process identifies
//! itself on the channel as an administrator, and the daemon's own check
//! decides. Declining the prompt starts nothing and sends nothing.

#![cfg(windows)]
#![allow(
    unsafe_code,
    reason = "an undocumented export found by ordinal, the shell's elevation prompt and a message \
              window have no safe wrapper; five calls, none touching the daemon's state"
)]

use std::path::Path;

use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONWARNING, MB_OK, MessageBoxW, SW_HIDE};

/// `SetPreferredAppMode`'s ordinal in `uxtheme.dll`.
const SET_PREFERRED_APP_MODE: usize = 135;
/// `FlushMenuThemes`' ordinal.
const FLUSH_MENU_THEMES: usize = 136;
/// `AllowDark`: dark where the person chose a dark theme, light otherwise.
const ALLOW_DARK: i32 = 1;

/// A null-terminated wide string.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Opts this process into dark context menus where Windows allows it.
///
/// Returns whether it did. Called once, before the menu is built.
pub fn prefer_dark_menus() -> bool {
    let name = wide("uxtheme.dll");
    // SAFETY: a system library by name, from the system directory the loader
    // searches first for a known DLL; the name outlives the call.
    let library = unsafe { LoadLibraryW(name.as_ptr()) };
    if library.is_null() {
        return false;
    }
    // SAFETY: an ordinal is passed as a pointer whose value is the ordinal,
    // which is what `GetProcAddress` documents for a lookup by ordinal.
    let (set, flush) = unsafe {
        (
            GetProcAddress(library, core::ptr::without_provenance(SET_PREFERRED_APP_MODE)),
            GetProcAddress(library, core::ptr::without_provenance(FLUSH_MENU_THEMES)),
        )
    };
    let (Some(set), Some(flush)) = (set, flush) else {
        return false;
    };
    // SAFETY: the exports at these ordinals take one `i32` and return one, and
    // take nothing and return nothing, respectively, on every Windows that has
    // them. The library stays loaded for the life of the process.
    unsafe {
        let set: unsafe extern "system" fn(i32) -> i32 = core::mem::transmute(set);
        let flush: unsafe extern "system" fn() = core::mem::transmute(flush);
        set(ALLOW_DARK);
        flush();
    }
    true
}

/// Runs `program` with `argument`, elevated, through Windows' own prompt.
///
/// Returns whether it was started: `false` when the person declined the prompt.
/// It does not wait for it.
pub fn run_elevated(program: &Path, argument: &str) -> bool {
    let verb = wide("runas");
    let file = wide(&program.display().to_string());
    let parameters = wide(argument);
    // SAFETY: every string outlives the call; no window owns the prompt, and no
    // working directory is given.
    let started = unsafe {
        ShellExecuteW(
            core::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            parameters.as_ptr(),
            core::ptr::null(),
            SW_HIDE,
        )
    };
    // Documented: greater than 32 is success; anything else, including the
    // person declining, is not.
    started as usize > 32
}

/// Shows `text` in a message window titled "peerfectly", and waits for it to be
/// closed.
///
/// For what the tray has to say while it starts. It is a desktop program with no
/// console, so what a console program would print to standard error would go
/// nowhere, and a tray that failed silently is a person wondering why no icon
/// appeared.
pub fn tell(text: &str) {
    let title = wide("peerfectly");
    let body = wide(text);
    // SAFETY: both strings outlive the call, and no window owns the message.
    unsafe {
        MessageBoxW(core::ptr::null_mut(), body.as_ptr(), title.as_ptr(), MB_OK | MB_ICONWARNING);
    }
}

#[cfg(test)]
mod tests {
    /// **The undocumented export is used here and nowhere else**, so that if it
    /// changes there is one place to look, and the fallback is one function.
    #[test]
    fn the_undocumented_export_is_only_used_here() {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![source];
        while let Some(directory) = stack.pop() {
            for entry in std::fs::read_dir(directory).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.ends_with("desktop.rs") {
                    continue;
                }
                let code = crate::code_of(&std::fs::read_to_string(&path).unwrap_or_default());
                for export in ["uxtheme", "SetPreferredAppMode", "FlushMenuThemes"] {
                    assert!(!code.contains(export), "`{export}` used in {}", path.display());
                }
            }
        }
    }
}

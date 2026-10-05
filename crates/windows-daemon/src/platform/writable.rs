//! Who, besides the system and administrators, may write somewhere.
//!
//! A privileged process started from a place an ordinary person can write is a
//! privileged process somebody else chooses the code for. So the daemon asks
//! this about the directory its own executable is in, and refuses to run when
//! the answer is anybody.
//!
//! # A decision, not a syscall
//!
//! Everything here is a **pure function over the access control as text**.
//! Reading the access control is the platform's job and is done once, in
//! [`super::protected::describe`]; deciding what it means is arithmetic, and
//! arithmetic can be tested with a string.
//!
//! That is the point. `pipe.rs` warns that *"a subtly wrong access control is
//! worse than none, because it claims a protection it does not deliver"* — and
//! the way this answers it is that every case below is a test, including the
//! ones nobody thinks of: an entry that is inherit-only, a right written in hex
//! rather than by name, a deny that is not an allow, and `WD` meaning two
//! entirely different things depending on which field it is in.
//!
//! # What an entry looks like
//!
//! ```text
//! (A;OICI;GA;;;BU)
//!  │ │    │     └── who: BU = Builtin Users
//!  │ │    └──────── what: GA = generic all
//!  │ └───────────── how it is inherited
//!  └─────────────── A = allow, D = deny
//! ```

#![cfg(windows)]

/// What is reported where there is no access control at all.
///
/// Not an account: it is the absence of any, which Windows reads as everybody.
pub const NOBODY_IS_STOPPED: &str = "everyone: no access control at all";

/// The accounts a privileged program may be written by.
///
/// Anything else writing where the daemon lives is somebody choosing its code.
/// `SY` and `BA` are the short forms; the long ones appear where a descriptor
/// was rendered without them.
const MAY: &[&str] = &[
    "SY",           // Local System
    "BA",           // Builtin Administrators
    "S-1-5-18",     // Local System, written out
    "S-1-5-32-544", // Builtin Administrators, written out
    // TrustedInstaller, which owns most of what Windows installs.
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// Rights, by name, that let the holder change what is there.
///
/// `WD` is **write DAC** here — in the account field the same two letters mean
/// *Everyone*, which is why this is matched against the rights field only and
/// never against the whole entry.
const WRITES: &[&str] = &["GA", "GW", "FA", "FW", "SD", "WD", "WO", "DC", "DE"];

/// The bits, where a right is written as a number.
///
/// Anything that creates, changes, deletes, or takes control of what is there.
const WRITE_BITS: u32 = 0x0000_0002  // FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x0000_0004  // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x0000_0010  // FILE_WRITE_EA
    | 0x0000_0040  // FILE_DELETE_CHILD
    | 0x0000_0100  // FILE_WRITE_ATTRIBUTES
    | 0x0001_0000  // DELETE
    | 0x0004_0000  // WRITE_DAC
    | 0x0008_0000  // WRITE_OWNER
    | 0x1000_0000  // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

/// Who may write here, besides the system and administrators.
///
/// Empty means nobody else can, which is the only answer a privileged program
/// may start on. What comes back are the accounts as the descriptor named them,
/// so that a refusal can say **who** rather than only that somebody can.
///
/// **No access control at all is the widest answer, not an empty one.** Windows
/// reads a descriptor with none as *everybody may do anything*, so it is named
/// here rather than read as nobody being listed.
///
/// An individual entry this cannot read is skipped: the descriptor comes from
/// [`super::protected::describe`], which asks the platform itself, so an entry
/// that will not parse means this code is behind rather than that a directory is
/// open — and refusing to start everywhere because of a parsing gap would be the
/// worse failure.
#[must_use]
pub fn who_else_can_write(sddl: &str) -> Vec<String> {
    let Some(dacl) = dacl_of(sddl) else { return vec![NOBODY_IS_STOPPED.to_owned()] };
    if dacl.to_ascii_uppercase().contains("NO_ACCESS_CONTROL") {
        return vec![NOBODY_IS_STOPPED.to_owned()];
    }

    let mut found = Vec::new();
    for entry in entries(dacl) {
        let fields: Vec<&str> = entry.split(';').collect();
        let (Some(kind), Some(flags), Some(rights), Some(who)) =
            (fields.first(), fields.get(1), fields.get(2), fields.get(5))
        else {
            continue;
        };

        // Only allow entries grant anything. A deny is not a way in.
        if !kind.eq_ignore_ascii_case("A") {
            continue;
        }
        // Inherit-only says nothing about this object: it is a rule for what is
        // made inside it later.
        if flags.to_ascii_uppercase().contains("IO") {
            continue;
        }
        if MAY.iter().any(|allowed| who.eq_ignore_ascii_case(allowed)) {
            continue;
        }
        if !grants_writing(rights) {
            continue;
        }
        let who = (*who).to_owned();
        if !found.contains(&who) {
            found.push(who);
        }
    }
    found
}

/// Whether a rights field lets the holder change what is there.
fn grants_writing(rights: &str) -> bool {
    let rights = rights.trim();
    if let Some(hex) = rights.strip_prefix("0x").or_else(|| rights.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).is_ok_and(|mask| mask & WRITE_BITS != 0);
    }
    // Named rights are two letters each, run together.
    rights
        .as_bytes()
        .chunks(2)
        .filter_map(|pair| core::str::from_utf8(pair).ok())
        .any(|pair| WRITES.iter().any(|write| pair.eq_ignore_ascii_case(write)))
}

/// The DACL part of a descriptor, if it has one.
///
/// A descriptor with no `D:` has no discretionary access control at all, which
/// Windows treats as *everyone may do anything*. That is the widest possible
/// answer and it is said as such rather than read as an absence.
fn dacl_of(sddl: &str) -> Option<&str> {
    let at = sddl.find("D:")?;
    let rest = &sddl[at.saturating_add(2)..];
    // The DACL runs to the next section, if there is one.
    let end =
        ["S:", "O:", "G:"].iter().filter_map(|next| rest.find(next)).min().unwrap_or(rest.len());
    rest.get(..end)
}

/// Each `(...)` entry of an access control.
fn entries(dacl: &str) -> impl Iterator<Item = &str> {
    dacl.split('(').skip(1).filter_map(|part| part.split(')').next())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the daemon's own directory should look like: nobody else.
    #[test]
    fn a_protected_directory_lets_nobody_else_write() {
        assert!(who_else_can_write("D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)").is_empty());
    }

    /// And what a build directory looks like, which is why the check exists.
    #[test]
    fn a_directory_an_ordinary_person_can_write_names_them() {
        let who = who_else_can_write("D:(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;BU)");
        assert_eq!(vec!["BU".to_owned()], who, "and says which account it is");
    }

    /// Rights are often a number, and a number is not a name.
    #[test]
    fn rights_written_as_a_number_are_read() {
        // 0x1301bf is the ordinary "modify" a person gets on their own files.
        assert_eq!(
            vec!["BU".to_owned()],
            who_else_can_write("D:(A;;0x1301bf;;;BU)"),
            "modify includes writing"
        );
        // 0x1200a9 is read and execute, which is not writing.
        assert!(
            who_else_can_write("D:(A;;0x1200a9;;;BU)").is_empty(),
            "reading and running is not changing"
        );
    }

    /// An inherit-only entry is a rule about what is made inside, later. It says
    /// nothing about who may write the directory now.
    #[test]
    fn an_inherit_only_entry_is_not_about_this_directory() {
        assert!(who_else_can_write("D:(A;OICIIO;GA;;;CO)(A;;GA;;;SY)").is_empty());
    }

    /// A deny is not a way in.
    #[test]
    fn a_denial_grants_nothing() {
        assert!(who_else_can_write("D:(D;;GA;;;BU)(A;;GA;;;SY)").is_empty());
    }

    /// **`WD` is two different things and only one of them is a right.**
    ///
    /// In the rights field it is *write DAC* — the holder may rewrite who else
    /// may do what, which is writing by a longer road. In the account field the
    /// same two letters are *Everyone*. A check that matched the string against
    /// the whole entry would confuse them, and would do it in the direction that
    /// looks safe.
    #[test]
    fn wd_in_one_field_is_not_wd_in_the_other() {
        assert_eq!(
            vec!["BU".to_owned()],
            who_else_can_write("D:(A;;WD;;;BU)"),
            "as a right it is writing the access control, which is writing"
        );
        assert_eq!(
            vec!["WD".to_owned()],
            who_else_can_write("D:(A;;GA;;;WD)"),
            "as an account it is everyone, which is also not nobody"
        );
    }

    /// The accounts written out rather than abbreviated are the same accounts.
    #[test]
    fn a_long_name_is_the_same_account_as_its_short_one() {
        assert!(
            who_else_can_write("D:(A;;GA;;;S-1-5-18)(A;;GA;;;S-1-5-32-544)").is_empty(),
            "the system and administrators, written out"
        );
    }

    /// **No access control at all means everyone may do anything**, which is the
    /// widest possible answer and must not read as *nobody listed*.
    ///
    /// Both spellings: a descriptor with no `D:` section, and the one Windows
    /// renders when the access control is explicitly absent.
    #[test]
    fn a_descriptor_with_no_access_control_is_not_a_safe_one() {
        for wide_open in ["O:BAG:BA", "D:NO_ACCESS_CONTROL", "O:BAG:BAD:NO_ACCESS_CONTROL"] {
            assert_eq!(
                vec![NOBODY_IS_STOPPED.to_owned()],
                who_else_can_write(wide_open),
                "`{wide_open}` is Windows for: anybody"
            );
        }
    }

    /// Reading only what is between the `D:` and the next section.
    #[test]
    fn what_is_audited_is_not_what_is_allowed() {
        assert!(
            who_else_can_write("D:(A;;GA;;;SY)S:(AU;SAFA;GA;;;WD)").is_empty(),
            "the audit section grants nothing"
        );
    }

    /// **The folder the installer makes passes without the override.** This is
    /// what a folder an installer creates under `%ProgramFiles%` carries on
    /// Windows 11, read with `Get-Acl` (the group, a person's own account, is
    /// written with made-up numbers). It inherits read-and-run for users and
    /// for app containers, full control for the system, administrators and
    /// TrustedInstaller, and creator-owner as a rule for what is made inside.
    #[test]
    fn a_folder_under_program_files_lets_nobody_else_write() {
        const INSTALLED: &str = "O:BAG:S-1-5-21-1-2-3-1001D:AI\
            (A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)\
            (A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)\
            (A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)\
            (A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)\
            (A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)\
            (A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)";
        assert_eq!(Vec::<String>::new(), who_else_can_write(INSTALLED));
    }

    /// One account listed twice is one account.
    #[test]
    fn the_same_account_is_named_once() {
        assert_eq!(
            vec!["BU".to_owned()],
            who_else_can_write("D:(A;;GW;;;BU)(A;;GA;;;BU)"),
            "said once, not once per entry"
        );
    }
}

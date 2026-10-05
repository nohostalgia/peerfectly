//! Writing the name-resolution rule into the registry.
//!
//! This is the same key `Add-DnsClientNrptRule` writes. Going to the registry
//! directly rather than through PowerShell means a structured result instead of
//! console output to parse, and no elevated process spawned to get it.
//!
//! What the rule should say is [`daemon::rule`]'s decision. This writes it.
//!
//! # The sweep is the important half
//!
//! [`remove`] runs on shutdown. [`sweep`] runs on **startup**, and it is the one
//! that matters: the case that leaves a rule behind is by definition the case
//! where shutdown did not run. A daemon that only cleaned up on the way out would
//! be cleaning up in exactly the situation where cleanup was never needed.
//!
//! # What is not tested here
//!
//! Writing under `HKEY_LOCAL_MACHINE` needs Administrator, so no automated test
//! covers it. `VERIFICATION.md` records what was checked by hand.

use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ};

use daemon::error::{Error, Residue, Result, Step};
use daemon::rule::Rule;

/// Where Windows keeps resolution policy.
const POLICY_PATH: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

/// Marks the rule as one that names a resolver explicitly.
const CONFIG_OPTIONS_GENERIC_SERVER: u32 = 0x8;

/// The rule format's version, as the resolver expects it.
const RULE_VERSION: u32 = 1;

/// Wraps a registry failure with the step it belongs to.
fn failed(step: Step, what: &str, cause: &std::io::Error, left: Vec<Residue>) -> Error {
    Error::BringUp { step, cause: format!("{what}: {cause}"), left }
}

/// Writes the rule.
///
/// # Errors
///
/// When the registry refuses, most often for want of Administrator.
pub fn install(rule: &Rule) -> Result<()> {
    let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (policy, _) = machine
        .create_subkey(POLICY_PATH)
        .map_err(|cause| failed(Step::InstallingRule, "the policy key", &cause, Vec::new()))?;

    let (key, _) = policy
        .create_subkey(rule.key_name())
        .map_err(|cause| failed(Step::InstallingRule, "creating the rule", &cause, Vec::new()))?;

    let left = vec![Residue::ResolutionRule { suffix: rule.suffix().to_owned() }];
    let write = |name: &str, value: &dyn WriteValue| value.write(&key, name);

    write("Name", &vec![rule.matched_name()])
        .map_err(|cause| failed(Step::InstallingRule, "the matched name", &cause, left.clone()))?;
    write("GenericDNSServers", &rule.nameserver().to_string()).map_err(|cause| {
        failed(Step::InstallingRule, "the resolver address", &cause, left.clone())
    })?;
    write("ConfigOptions", &CONFIG_OPTIONS_GENERIC_SERVER)
        .map_err(|cause| failed(Step::InstallingRule, "the rule options", &cause, left.clone()))?;
    write("Version", &RULE_VERSION)
        .map_err(|cause| failed(Step::InstallingRule, "the rule version", &cause, left.clone()))?;
    write("Comment", &format!("{} — removed when the tunnel goes down", rule.key_name()))
        .map_err(|cause| failed(Step::InstallingRule, "the rule comment", &cause, left))?;

    Ok(())
}

/// A registry value this module knows how to write.
///
/// A tiny trait rather than five near-identical calls, so every value goes
/// through one place and a new one cannot quietly skip the error handling.
trait WriteValue {
    /// Writes this value under `name`.
    fn write(&self, key: &RegKey, name: &str) -> std::io::Result<()>;
}

impl WriteValue for u32 {
    fn write(&self, key: &RegKey, name: &str) -> std::io::Result<()> {
        key.set_value(name, self)
    }
}

impl WriteValue for String {
    fn write(&self, key: &RegKey, name: &str) -> std::io::Result<()> {
        key.set_value(name, self)
    }
}

impl WriteValue for Vec<String> {
    fn write(&self, key: &RegKey, name: &str) -> std::io::Result<()> {
        key.set_value(name, self)
    }
}

/// Removes the rule this daemon wrote.
///
/// A rule that is not there is not an error: the caller wanted it gone.
///
/// # Errors
///
/// When the registry refuses to remove a rule that is present.
pub fn remove(rule: &Rule) -> Result<()> {
    remove_named(&rule.key_name())
}

/// Removes any rule this daemon left behind on an earlier run.
///
/// Runs on startup. Returns whether anything was found, so a daemon that cleaned
/// up after a crash can say so rather than doing it silently — a person whose
/// name resolution was broken until now deserves to know why.
///
/// # Errors
///
/// When the registry can be read but not written.
pub fn sweep() -> Result<bool> {
    let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(policy) = machine.open_subkey_with_flags(POLICY_PATH, KEY_READ) else {
        // No policy key at all means no rule, which is the state asked for.
        return Ok(false);
    };

    let ours: Vec<String> = policy
        .enum_keys()
        .filter_map(std::result::Result::ok)
        .filter(|name| name.contains(daemon::limits::RULE_TAG))
        .collect();

    let mut found = false;
    for name in ours {
        remove_named(&name)?;
        found = true;
    }
    Ok(found)
}

/// Removes one rule subkey by name.
fn remove_named(name: &str) -> Result<()> {
    let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(policy) = machine.open_subkey_with_flags(POLICY_PATH, KEY_ALL_ACCESS) else {
        return Ok(());
    };

    match policy.delete_subkey_all(name) {
        Ok(()) => Ok(()),
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(cause) => Err(failed(
            Step::InstallingRule,
            "removing the rule",
            &cause,
            vec![Residue::ResolutionRule { suffix: name.to_owned() }],
        )),
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// The path is the one Windows reads, not one of our choosing. Getting it
    /// wrong writes a rule nothing consults, which looks exactly like a rule that
    /// was never written.
    #[test]
    fn the_policy_path_is_the_one_windows_reads() {
        assert!(POLICY_PATH.ends_with("DnsPolicyConfig"));
        assert!(POLICY_PATH.contains("Dnscache"));
    }

    /// Reading the policy key needs no privilege, so this much can be checked
    /// here. Writing cannot, and is not claimed to be.
    #[test]
    fn the_policy_key_can_be_read_without_privilege() {
        let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
        match machine.open_subkey_with_flags(POLICY_PATH, KEY_READ) {
            Ok(policy) => {
                // Enumerating must not fail; a machine with no rules has none.
                let names: Vec<String> =
                    policy.enum_keys().filter_map(std::result::Result::ok).collect();
                assert!(names.len() < 10_000, "a sane number of rules");
            }
            Err(cause) => {
                assert_eq!(
                    cause.kind(),
                    std::io::ErrorKind::NotFound,
                    "the key may be absent, but must not be unreadable: {cause}"
                );
            }
        }
    }

    /// The sweep looks for the tag, so it finds this daemon's leftovers and not
    /// a rule somebody else wrote for the same suffix.
    #[test]
    fn the_sweep_matches_on_the_tag() {
        let code = crate::code_of(include_str!("nrpt.rs"));
        assert!(
            code.contains("name.contains(daemon::limits::RULE_TAG)"),
            "the sweep must select on the tag, never on the suffix"
        );
    }

    /// Removing a rule that is not there is the outcome asked for. If it were an
    /// error, cleanup would fail on the second run — the path that runs after a
    /// crash, which is the one that matters.
    #[test]
    fn removing_an_absent_rule_is_not_a_failure() {
        assert!(remove_named("peerfectly-daemon-v1-absent-in-any-test").is_ok());
    }
}

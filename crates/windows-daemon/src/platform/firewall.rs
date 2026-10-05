//! The machine's firewall, through the COM API its own tools use (F-11).
//!
//! `INetFwPolicy2` rather than raw filtering-platform filters: rules written here
//! are the ones `wf.msc` shows and a person can remove, and Windows Firewall
//! arbitrates its own allow and block rules — a permit filter in a sublayer of
//! our own does not reliably win over a firewall block in another.
//!
//! **Every call runs on a blocking thread that initialises COM around it**, so no
//! async worker is ever left initialised in a mode something else did not expect.
//!
//! **A rule is removed by name only when every rule carrying that name is ours.**
//! The API removes by name, and Windows' own prompt names a program's rules after
//! the program, so a name alone could reach a rule somebody else wrote.
//!
//! # Why the `unsafe` is here
//!
//! The firewall is a COM API, and every call through the `windows` crate's
//! bindings is `unsafe`. Nothing here decides anything: what a rule admits is
//! decided in `daemon::exposing`, where it is tested.

#![cfg(windows)]
#![allow(
    unsafe_code,
    reason = "the firewall is a COM API with no safe wrapper; the unsafe surface is confined to \
              this module, as `custody` and `route_table` confine theirs"
)]

use std::path::Path;

use daemon::exposing::{Exposing, GROUP, Held, Protocol, Rule, network_of};
use roster::id::NetworkId;
use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NET_FW_ACTION_ALLOW, NET_FW_PROFILE2_ALL,
    NET_FW_RULE_DIR_IN, NetFwPolicy2, NetFwRule,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::Ole::{
    IEnumVARIANT, SafeArrayCreateVector, SafeArrayDestroy, SafeArrayPutElement,
};
use windows::Win32::System::Variant::{
    VARENUM, VARIANT, VT_ARRAY, VT_BSTR, VT_DISPATCH, VT_VARIANT, VariantClear,
};
use windows::core::{BSTR, Interface};

/// The name of the daemon's own rule for its transport.
pub const DAEMON_RULE: &str = "peerfectly daemon (UDP)";

/// The machine's firewall.
pub struct Firewall;

/// COM, initialised for as long as this lives, on this thread.
struct Com {
    /// Whether this thread's initialisation was ours to undo.
    ours: bool,
}

impl Com {
    fn new() -> Self {
        // S_FALSE means already initialised in this mode, and is still ours to
        // balance; a different mode already set is not, and the calls still work.
        let status = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        Self { ours: status.is_ok() }
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.ours {
            unsafe { CoUninitialize() };
        }
    }
}

/// Runs `work` on a blocking thread with COM initialised around it.
async fn on_com<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(move || {
        let _com = Com::new();
        work()
    })
    .await
    .map_err(|cause| format!("the firewall call did not finish: {cause}"))?
}

/// Runs `work` on this thread, with COM initialised around it. For callers
/// that are not in an async context, such as install.
fn with_com<T>(work: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let _com = Com::new();
    work()
}

fn failed(doing: &str) -> impl Fn(windows::core::Error) -> String + '_ {
    move |cause| format!("the firewall would not {doing}: {cause}")
}

/// The machine's rule collection.
fn rules() -> Result<INetFwRules, String> {
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
            .map_err(failed("open"))?;
    unsafe { policy.Rules() }.map_err(failed("list its rules"))
}

/// Every rule the firewall holds.
fn every_rule(rules: &INetFwRules) -> Result<Vec<INetFwRule>, String> {
    let enumerator: IEnumVARIANT = unsafe { rules._NewEnum() }
        .and_then(|unknown| unknown.cast())
        .map_err(failed("list its rules"))?;
    let mut found = Vec::new();
    loop {
        let mut slot = [VARIANT::default()];
        let mut fetched = 0_u32;
        let status = unsafe { enumerator.Next(&mut slot, &raw mut fetched) };
        if status.is_err() || fetched == 0 {
            break;
        }
        let [mut item] = slot;
        // A rule arrives as the dispatch interface of its object.
        let rule = unsafe {
            let inner = &item.Anonymous.Anonymous;
            if inner.vt == VT_DISPATCH {
                inner
                    .Anonymous
                    .pdispVal
                    .as_ref()
                    .and_then(|dispatch| dispatch.cast::<INetFwRule>().ok())
            } else {
                None
            }
        };
        let _ = unsafe { VariantClear(&raw mut item) };
        if let Some(rule) = rule {
            found.push(rule);
        }
    }
    Ok(found)
}

fn text(read: windows::core::Result<BSTR>) -> String {
    read.map(|value| value.to_string()).unwrap_or_default()
}

/// One of ours, read back: an exposure rule in our group naming a network.
fn exposure(rule: &INetFwRule) -> Option<(Held, String)> {
    if text(unsafe { rule.Grouping() }) != GROUP {
        return None;
    }
    let network = network_of(&text(unsafe { rule.Description() }))?;
    let protocol = match unsafe { rule.Protocol() }.ok()? {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return None,
    };
    let port = text(unsafe { rule.LocalPorts() }).parse().ok()?;
    Some((Held { network, protocol, port }, text(unsafe { rule.Name() })))
}

/// Removes `name`, when every rule carrying it satisfies `ours`. Whether it did.
fn remove_if_all_ours(
    rules: &INetFwRules,
    name: &str,
    ours: impl Fn(&INetFwRule) -> bool,
) -> Result<bool, String> {
    let all = every_rule(rules)?;
    let named: Vec<&INetFwRule> =
        all.iter().filter(|rule| text(unsafe { rule.Name() }) == name).collect();
    if named.is_empty() || !named.iter().all(|rule| ours(rule)) {
        return Ok(false);
    }
    // One call per rule carrying the name: the API removes one at a time.
    for _ in &named {
        unsafe { rules.Remove(&BSTR::from(name)) }.map_err(failed("remove a rule"))?;
    }
    Ok(true)
}

/// A variant holding an array of one string, as `INetFwRule::Interfaces` takes.
fn one_name(name: &str) -> Result<VARIANT, String> {
    unsafe {
        let array = SafeArrayCreateVector(VT_VARIANT, 0, 1);
        if array.is_null() {
            return Err("the firewall's interface list could not be made".to_owned());
        }
        let mut element = VARIANT::default();
        {
            let inner = &mut *element.Anonymous.Anonymous;
            inner.vt = VT_BSTR;
            inner.Anonymous.bstrVal = core::mem::ManuallyDrop::new(BSTR::from(name));
        }
        // Copied into the array; ours is cleared either way.
        let first = 0_i32;
        let put = SafeArrayPutElement(array, &raw const first, (&raw const element).cast());
        let _ = VariantClear(&raw mut element);
        if let Err(cause) = put {
            let _ = SafeArrayDestroy(array);
            return Err(failed("take the interface's name")(cause));
        }

        let mut list = VARIANT::default();
        {
            let inner = &mut *list.Anonymous.Anonymous;
            inner.vt = VARENUM(VT_ARRAY.0 | VT_VARIANT.0);
            inner.Anonymous.parray = array;
        }
        Ok(list)
    }
}

fn add_exposure(rules: &INetFwRules, wanted: &Rule) -> Result<(), String> {
    let set = failed("take the rule");
    unsafe {
        let rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)
            .map_err(failed("make a rule"))?;
        rule.SetName(&BSTR::from(wanted.name.as_str())).map_err(&set)?;
        rule.SetDescription(&BSTR::from(wanted.description.as_str())).map_err(&set)?;
        rule.SetGrouping(&BSTR::from(GROUP)).map_err(&set)?;
        rule.SetDirection(NET_FW_RULE_DIR_IN).map_err(&set)?;
        rule.SetAction(NET_FW_ACTION_ALLOW).map_err(&set)?;
        rule.SetProtocol(wanted.protocol.number()).map_err(&set)?;
        rule.SetLocalPorts(&BSTR::from(wanted.port.to_string())).map_err(&set)?;
        rule.SetRemoteAddresses(&BSTR::from(wanted.remote_addresses.as_str())).map_err(&set)?;
        let mut interfaces = one_name(&wanted.interface)?;
        let bound = rule.SetInterfaces(&interfaces);
        let _ = VariantClear(&raw mut interfaces);
        bound.map_err(&set)?;
        // Every profile: the adapter is Public, and a rule limited to Private
        // would never apply to it.
        rule.SetProfiles(NET_FW_PROFILE2_ALL.0).map_err(&set)?;
        rule.SetEnabled(VARIANT_TRUE).map_err(&set)?;
        rules.Add(&rule).map_err(failed("add the rule"))
    }
}

fn matching(held: &Held, network: &NetworkId, protocol: Protocol, port: u16) -> bool {
    held.network == *network && held.protocol == protocol && held.port == port
}

/// Removes our rules chosen by `which`. How many went.
fn remove_ours(rules: &INetFwRules, which: impl Fn(&Held) -> bool) -> Result<usize, String> {
    let names: Vec<String> = every_rule(rules)?
        .iter()
        .filter_map(exposure)
        .filter(|(held, _)| which(held))
        .map(|(_, name)| name)
        .collect();
    let mut gone = 0_usize;
    for name in names {
        if remove_if_all_ours(rules, &name, |rule| {
            exposure(rule).is_some_and(|(held, _)| which(&held))
        })? {
            gone = gone.saturating_add(1);
        }
    }
    Ok(gone)
}

#[async_trait::async_trait]
impl Exposing for Firewall {
    async fn expose(&self, rule: &Rule) -> Result<(), String> {
        let wanted = rule.clone();
        on_com(move || {
            let rules = rules()?;
            // Replaced, not duplicated: exposing what is exposed leaves one rule.
            let _ = remove_ours(&rules, |held| {
                matching(held, &wanted.network, wanted.protocol, wanted.port)
            })?;
            add_exposure(&rules, &wanted)
        })
        .await
    }

    async fn unexpose(
        &self,
        network: &NetworkId,
        protocol: Protocol,
        port: u16,
    ) -> Result<bool, String> {
        let network = *network;
        on_com(move || {
            let rules = rules()?;
            Ok(remove_ours(&rules, |held| matching(held, &network, protocol, port))? > 0)
        })
        .await
    }

    async fn held(&self) -> Result<Vec<Held>, String> {
        on_com(|| {
            Ok(every_rule(&rules()?)?.iter().filter_map(exposure).map(|(held, _)| held).collect())
        })
        .await
    }

    async fn forget(&self, network: &NetworkId) -> Result<usize, String> {
        let network = *network;
        on_com(move || remove_ours(&rules()?, |held| held.network == network)).await
    }

    async fn sweep(&self, kept: &[NetworkId]) -> Result<usize, String> {
        let kept = kept.to_vec();
        on_com(move || remove_ours(&rules()?, |held| !kept.contains(&held.network))).await
    }
}

/// Whether a rule is an inbound rule for `program`.
fn for_program(rule: &INetFwRule, program: &str) -> bool {
    text(unsafe { rule.ApplicationName() }).eq_ignore_ascii_case(program)
        && unsafe { rule.Direction() }.is_ok_and(|direction| direction == NET_FW_RULE_DIR_IN)
}

/// What installing did to the program's rules.
pub struct Narrowed {
    /// The rules for the program that were removed, by name.
    pub removed: Vec<String>,
    /// Names left alone, because another program's rule carries the same one.
    pub kept: Vec<String>,
}

/// Replaces every inbound rule for `program` with one admitting UDP alone (D6).
///
/// # Errors
///
/// When the firewall will not list, remove or add.
pub fn narrow_program(program: &Path) -> Result<Narrowed, String> {
    let program = program.display().to_string();
    with_com(|| {
        let rules = rules()?;
        let mut names: Vec<String> = every_rule(&rules)?
            .iter()
            .filter(|rule| for_program(rule, &program))
            .map(|rule| text(unsafe { rule.Name() }))
            .collect();
        names.sort();
        names.dedup();

        let mut narrowed = Narrowed { removed: Vec::new(), kept: Vec::new() };
        for name in names {
            if remove_if_all_ours(&rules, &name, |rule| for_program(rule, &program))? {
                narrowed.removed.push(name);
            } else {
                narrowed.kept.push(name);
            }
        }

        let set = failed("take the rule");
        unsafe {
            let rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)
                .map_err(failed("make a rule"))?;
            rule.SetName(&BSTR::from(DAEMON_RULE)).map_err(&set)?;
            rule.SetDescription(&BSTR::from(
                "peerfectly's transport: QUIC over UDP. Made by `peerfectlyd install`, removed by `peerfectlyd uninstall`.",
            ))
            .map_err(&set)?;
            rule.SetGrouping(&BSTR::from(GROUP)).map_err(&set)?;
            rule.SetApplicationName(&BSTR::from(program.as_str())).map_err(&set)?;
            rule.SetDirection(NET_FW_RULE_DIR_IN).map_err(&set)?;
            rule.SetAction(NET_FW_ACTION_ALLOW).map_err(&set)?;
            rule.SetProtocol(Protocol::Udp.number()).map_err(&set)?;
            rule.SetProfiles(NET_FW_PROFILE2_ALL.0).map_err(&set)?;
            rule.SetEnabled(VARIANT_TRUE).map_err(&set)?;
            rules.Add(&rule).map_err(failed("add the rule"))?;
        }
        Ok(narrowed)
    })
}

/// Removes the daemon's own rule for `program`. How many went.
///
/// # Errors
///
/// When the firewall will not list or remove.
pub fn remove_program_rule(program: &Path) -> Result<usize, String> {
    let program = program.display().to_string();
    with_com(|| {
        let rules = rules()?;
        let ours = |rule: &INetFwRule| {
            for_program(rule, &program) && text(unsafe { rule.Grouping() }) == GROUP
        };
        Ok(usize::from(remove_if_all_ours(&rules, DAEMON_RULE, ours)?))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reading the rules needs no Administrator and changes nothing, so it runs
    /// here: the enumeration and the reading-back are exercised on a real
    /// firewall, and whatever this machine holds, reading it does not fail.
    #[tokio::test]
    async fn the_firewall_can_be_read() {
        let held = Firewall.held().await;
        assert!(held.is_ok(), "{held:?}");
    }

    /// COM is created here and nowhere else in the crate, so every firewall call
    /// goes through the one place that initialises it around the work.
    #[test]
    fn nothing_else_opens_the_firewall() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut pending = vec![root];
        let mut read = 0_usize;
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).expect("lists").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().is_none_or(|extension| extension != "rs")
                    || path.ends_with("firewall.rs")
                {
                    continue;
                }
                read = read.saturating_add(1);
                let code = crate::code_of(&std::fs::read_to_string(&path).expect("reads"));
                for forbidden in ["NetFwPolicy2", "INetFwRule", "CoInitializeEx"] {
                    assert!(
                        !code.contains(forbidden),
                        "{} reaches the firewall directly: {forbidden}",
                        path.display()
                    );
                }
            }
        }
        assert!(read > 10, "the sources were found: {read}");
    }
}

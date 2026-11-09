//! A network's parameters as leaves of the state tree, one per parameter.
//!
//! Each parameter is a leaf of its own so that it can be proved, fetched and
//! changed on its own: a light member fetches the anchor list or the access
//! policy without the rest, and two admins changing different parameters at
//! once both take effect.
//!
//! # One spelling per value
//!
//! A leaf is **absent** when its parameter has its default — no IPv4 range
//! chosen, no relay, not moving, no anchors, no policy — and a present leaf
//! must carry something else. An empty anchor list written out would be a
//! second spelling of no anchors, and so a second root for one state; it is
//! refused.
//!
//! A leaf whose name this format does not know is refused, never skipped: the
//! thing skipped might be the policy that keeps a group out.

use alloc::string::String;
use alloc::vec::Vec;

use crate::cbor::{Reader, Writer};
use crate::error::{Error, Result};
use crate::id::DeviceId;
use crate::leaf::Group;
use crate::limits;
use crate::merkle::{self, Hash};
use crate::types::{Excluded, IPV4_RANGE_LEN, Ipv4Range, LEAVING_SCHEMA, Leaving, NetworkParams};

/// The context a parameter's position is derived under.
const POSITION_CONTEXT: &str = "peerfectly parameter position v1";

/// The context a parameter's value is hashed under.
const VALUE_CONTEXT: &str = "peerfectly parameter leaf v1";

/// Canonical key order of a policy rule.
pub const RULE_SCHEMA: &[&str] = &["to", "from"];

/// Every parameter name this format knows.
pub const PARAMETER_NAMES: &[&str] =
    &["ipv4", "policy", "prefix", "relays", "suffix", "window", "anchors", "leaving", "excluded"];

/// A rule of the access policy: members of `from` may open sessions to
/// members of `to`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rule {
    /// The group allowed to open the session.
    pub from: Group,
    /// The group it may be opened to.
    pub to: Group,
}

/// One parameter, as a leaf of the state tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parameter {
    /// The IPv6 unique local prefix.
    Prefix(Vec<u8>),
    /// The DNS suffix.
    Suffix(String),
    /// The IPv4 range, when one was chosen.
    Ipv4(Ipv4Range),
    /// The relays, as `key@host:port`. Exactly one in this version.
    Relays(Vec<String>),
    /// The relay being left during a move.
    Leaving(Leaving),
    /// The anchors, sorted and without repeats.
    Anchors(Vec<DeviceId>),
    /// The access policy's rules, sorted and without repeats.
    Policy(Vec<Rule>),
    /// The freshness window, in seconds.
    Window(u64),
    /// The blocks excluded from the network's IPv4 route, sorted and without
    /// repeats.
    Excluded(Vec<Excluded>),
}

impl Parameter {
    /// The parameter's name, which fixes its position in the tree.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Prefix(_) => "prefix",
            Self::Suffix(_) => "suffix",
            Self::Ipv4(_) => "ipv4",
            Self::Relays(_) => "relays",
            Self::Leaving(_) => "leaving",
            Self::Anchors(_) => "anchors",
            Self::Policy(_) => "policy",
            Self::Window(_) => "window",
            Self::Excluded(_) => "excluded",
        }
    }

    /// Where a parameter called `name` sits in the parameter tree.
    #[must_use]
    pub fn position(name: &str) -> Hash {
        blake3::derive_key(POSITION_CONTEXT, name.as_bytes())
    }

    /// The hash the parameter tree holds for this leaf.
    #[must_use]
    pub fn value_hash(&self) -> Hash {
        blake3::derive_key(VALUE_CONTEXT, &self.value_bytes())
    }

    /// The value's canonical bytes.
    #[must_use]
    pub fn value_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        match self {
            Self::Prefix(prefix) => {
                writer.bytes(prefix);
            }
            Self::Suffix(suffix) => {
                writer.str(suffix);
            }
            Self::Ipv4(range) => {
                writer.bytes(&range.to_bytes());
            }
            Self::Relays(relays) => {
                writer.array(relays.len() as u64);
                for relay in relays {
                    writer.str(relay);
                }
            }
            Self::Leaving(leaving) => {
                writer.map(2);
                writer.key("relay").str(&leaving.relay);
                writer.key("until").u64(leaving.until);
            }
            Self::Anchors(anchors) => write_anchors(&mut writer, anchors),
            Self::Policy(rules) => write_policy(&mut writer, rules),
            Self::Excluded(excluded) => write_excluded(&mut writer, excluded),
            Self::Window(seconds) => {
                writer.u64(*seconds);
            }
        }
        writer.finish()
    }

    /// Reads the parameter called `name` from its value's bytes.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownField`] for a name this format does not know; otherwise
    /// any error of the value's own checks, including a value that spells the
    /// parameter's default, which has no leaf.
    pub fn decode(name: &str, value: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(value);
        let parameter = match name {
            "prefix" => {
                let prefix =
                    reader.bytes(limits::MAX_ULA_PREFIX_LEN, "ula prefix length")?.to_vec();
                crate::params::unique_local_prefix(&prefix)?;
                Self::Prefix(prefix)
            }
            "suffix" => {
                let suffix = String::from(reader.str(limits::MAX_SUFFIX_LEN, "suffix length")?);
                crate::params::private_suffix(&suffix)?;
                Self::Suffix(suffix)
            }
            "ipv4" => Self::Ipv4(Ipv4Range::from_bytes(
                reader.bytes(IPV4_RANGE_LEN.saturating_add(1), "ipv4 range length")?,
            )?),
            "relays" => {
                let count = reader.array(1, "relays")?;
                let mut relays = Vec::with_capacity(count);
                for _ in 0..count {
                    relays.push(String::from(
                        reader.str(limits::MAX_RELAY_LEN, "relay address length")?,
                    ));
                }
                Self::relays(relays)?
            }
            "leaving" => {
                let mut map = reader.map(LEAVING_SCHEMA)?;
                let relay = String::from(
                    map.key("relay")?.str(limits::MAX_RELAY_LEN, "relay address length")?,
                );
                let until = map.key("until")?.u64()?;
                map.finish()?;
                Self::Leaving(Leaving { relay, until })
            }
            "anchors" => Self::anchors(read_anchors(&mut reader)?)?,
            "policy" => Self::policy(read_policy(&mut reader)?)?,
            "window" => Self::window(reader.u64()?)?,
            "excluded" => Self::excluded(read_excluded(&mut reader)?)?,
            _ => return Err(Error::UnknownField),
        };
        reader.finish()?;
        Ok(parameter)
    }

    /// The relay list, refusing an empty list and more than one relay.
    ///
    /// # Errors
    ///
    /// When the list is empty — no relay is the leaf left out — or holds more
    /// than one: a network carried across relays needs relays that forward to
    /// each other, which this version does not have.
    pub fn relays(relays: Vec<String>) -> Result<Self> {
        match relays.as_slice() {
            [] => Err(Error::InvalidValue("an empty relay list is no relay, which has no leaf")),
            [relay] if relay.is_empty() => Err(Error::InvalidValue("empty relay address")),
            [_] => Ok(Self::Relays(relays)),
            _ => Err(Error::InvalidValue("networks across several relays are not supported yet")),
        }
    }

    /// The anchor list, sorted, refusing an empty list and excess.
    ///
    /// # Errors
    ///
    /// When it is empty, too long, or repeats an anchor.
    pub fn anchors(mut anchors: Vec<DeviceId>) -> Result<Self> {
        if anchors.is_empty() {
            return Err(Error::InvalidValue(
                "an empty anchor list is no anchors, which has no leaf",
            ));
        }
        if anchors.len() > limits::MAX_ANCHORS {
            return Err(Error::LimitExceeded("anchors"));
        }
        anchors.sort();
        if !strictly_ascending(&anchors) {
            return Err(Error::InvalidValue("repeated anchor"));
        }
        Ok(Self::Anchors(anchors))
    }

    /// The access policy, sorted, refusing an empty policy and excess.
    ///
    /// # Errors
    ///
    /// When it is empty, too long, or repeats a rule.
    pub fn policy(mut rules: Vec<Rule>) -> Result<Self> {
        if rules.is_empty() {
            return Err(Error::InvalidValue("an empty policy is no policy, which has no leaf"));
        }
        if rules.len() > limits::MAX_POLICY_RULES {
            return Err(Error::LimitExceeded("policy rules"));
        }
        rules.sort();
        if !strictly_ascending(&rules) {
            return Err(Error::InvalidValue("repeated policy rule"));
        }
        Ok(Self::Policy(rules))
    }

    /// The excluded blocks, sorted, refusing an empty list and excess.
    ///
    /// # Errors
    ///
    /// When it is empty, too long, or repeats a block.
    pub fn excluded(mut excluded: Vec<Excluded>) -> Result<Self> {
        if excluded.is_empty() {
            return Err(Error::InvalidValue(
                "an empty excluded list is nothing excluded, which has no leaf",
            ));
        }
        if excluded.len() > Excluded::MAX {
            return Err(Error::LimitExceeded("excluded blocks"));
        }
        excluded.sort();
        if !strictly_ascending(&excluded) {
            return Err(Error::InvalidValue("repeated excluded block"));
        }
        Ok(Self::Excluded(excluded))
    }

    /// The freshness window, refusing zero.
    ///
    /// # Errors
    ///
    /// When it is zero, which would be a network always stale.
    pub fn window(seconds: u64) -> Result<Self> {
        if seconds == 0 {
            return Err(Error::InvalidValue("a freshness window of zero"));
        }
        Ok(Self::Window(seconds))
    }
}

/// Writes an anchor list.
pub(crate) fn write_anchors(writer: &mut Writer, anchors: &[DeviceId]) {
    writer.array(anchors.len() as u64);
    for anchor in anchors {
        anchor.encode(writer);
    }
}

/// Reads an anchor list, refusing one out of order or repeated.
pub(crate) fn read_anchors(reader: &mut Reader<'_>) -> Result<Vec<DeviceId>> {
    let count = reader.array(limits::MAX_ANCHORS, "anchors")?;
    let mut anchors = Vec::with_capacity(count);
    for _ in 0..count {
        anchors.push(DeviceId::decode(reader)?);
    }
    if !strictly_ascending(&anchors) {
        return Err(Error::NonCanonical);
    }
    Ok(anchors)
}

/// Writes an excluded list.
pub(crate) fn write_excluded(writer: &mut Writer, excluded: &[Excluded]) {
    writer.array(excluded.len() as u64);
    for block in excluded {
        writer.bytes(&block.to_bytes());
    }
}

/// Reads an excluded list, refusing one out of order or repeated.
pub(crate) fn read_excluded(reader: &mut Reader<'_>) -> Result<Vec<Excluded>> {
    let count = reader.array(Excluded::MAX, "excluded blocks")?;
    let mut excluded = Vec::with_capacity(count);
    for _ in 0..count {
        excluded.push(Excluded::from_bytes(
            reader.bytes(IPV4_RANGE_LEN.saturating_add(1), "excluded block length")?,
        )?);
    }
    if !strictly_ascending(&excluded) {
        return Err(Error::NonCanonical);
    }
    Ok(excluded)
}

/// Writes an access policy.
pub(crate) fn write_policy(writer: &mut Writer, rules: &[Rule]) {
    writer.array(rules.len() as u64);
    for rule in rules {
        writer.map(2);
        writer.key("to").str(rule.to.as_str());
        writer.key("from").str(rule.from.as_str());
    }
}

/// Reads an access policy, refusing one out of order or repeated.
pub(crate) fn read_policy(reader: &mut Reader<'_>) -> Result<Vec<Rule>> {
    let count = reader.array(limits::MAX_POLICY_RULES, "policy rules")?;
    let mut rules = Vec::with_capacity(count);
    for _ in 0..count {
        let mut map = reader.map(RULE_SCHEMA)?;
        let to = Group::new(map.key("to")?.str(limits::MAX_GROUP_LEN, "group name length")?)?;
        let from = Group::new(map.key("from")?.str(limits::MAX_GROUP_LEN, "group name length")?)?;
        map.finish()?;
        rules.push(Rule { from, to });
    }
    if !strictly_ascending(&rules) {
        return Err(Error::NonCanonical);
    }
    Ok(rules)
}

/// Whether every item is greater than the one before it.
fn strictly_ascending<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| matches!(pair, [first, second] if first < second))
}

impl NetworkParams {
    /// The parameters as leaves, one per parameter that is not at its default.
    #[must_use]
    pub fn leaves(&self) -> Vec<Parameter> {
        let mut leaves = alloc::vec![
            Parameter::Prefix(self.ula.clone()),
            Parameter::Suffix(self.suffix.clone())
        ];
        if let Some(range) = self.ipv4 {
            leaves.push(Parameter::Ipv4(range));
        }
        if let Some(relay) = &self.relay {
            leaves.push(Parameter::Relays(alloc::vec![relay.clone()]));
        }
        if let Some(leaving) = &self.leaving {
            leaves.push(Parameter::Leaving(leaving.clone()));
        }
        if !self.anchors.is_empty() {
            leaves.push(Parameter::Anchors(self.anchors.clone()));
        }
        if !self.policy.is_empty() {
            leaves.push(Parameter::Policy(self.policy.clone()));
        }
        if !self.excluded.is_empty() {
            leaves.push(Parameter::Excluded(self.excluded.clone()));
        }
        if self.snapshot_window != 0 {
            leaves.push(Parameter::Window(self.snapshot_window));
        }
        leaves
    }

    /// The root of the parameter tree.
    #[must_use]
    pub fn tree(&self) -> merkle::Tree {
        let mut tree = merkle::Tree::new();
        for leaf in self.leaves() {
            tree.insert(Parameter::position(leaf.name()), leaf.value_hash());
        }
        tree
    }

    /// Parameters built from their leaves.
    ///
    /// # Errors
    ///
    /// When a parameter appears twice, when the prefix, suffix or window is
    /// missing, or when the leaves together break a rule the parameters keep,
    /// such as a relay being left with no relay to move to.
    pub fn from_leaves(leaves: Vec<Parameter>) -> Result<Self> {
        let mut seen: Vec<&'static str> = Vec::new();
        let mut prefix = None;
        let mut suffix = None;
        let mut window = None;
        let mut ipv4 = None;
        let mut relay = None;
        let mut leaving = None;
        let mut anchors = Vec::new();
        let mut policy = Vec::new();
        let mut excluded = Vec::new();
        for leaf in leaves {
            if seen.contains(&leaf.name()) {
                return Err(Error::DuplicateKey);
            }
            seen.push(leaf.name());
            match leaf {
                Parameter::Prefix(value) => prefix = Some(value),
                Parameter::Suffix(value) => suffix = Some(value),
                Parameter::Window(value) => window = Some(value),
                Parameter::Ipv4(value) => ipv4 = Some(value),
                Parameter::Relays(mut relays) => relay = relays.pop(),
                Parameter::Leaving(value) => leaving = Some(value),
                Parameter::Anchors(value) => anchors = value,
                Parameter::Policy(value) => policy = value,
                Parameter::Excluded(value) => excluded = value,
            }
        }
        let (Some(prefix), Some(suffix)) = (prefix, suffix) else {
            return Err(Error::MissingField);
        };
        // No window leaf is no window.
        let window = window.unwrap_or(0);
        let mut params = Self::with_relay(prefix, relay, suffix, window)?;
        params.ipv4 = ipv4;
        params.anchors = anchors;
        params.policy = policy;
        params.excluded = excluded;
        match leaving {
            Some(leaving) => params.leaving(leaving),
            None => Ok(params),
        }
    }
}

/// Whether the access policy lets a member of `from` open a session to a member
/// of `to`.
///
/// No policy lets everyone reach everyone. With one, a session is allowed only
/// where a rule leads from one of the initiator's groups to one of the
/// receiver's: a device in no group reaches nobody, and is reached by nobody.
#[must_use]
pub fn allows(policy: &[Rule], from: &[Group], to: &[Group]) -> bool {
    policy.is_empty()
        || policy.iter().any(|rule| from.contains(&rule.from) && to.contains(&rule.to))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::cbor::is_canonical_schema;

    fn group(name: &str) -> Group {
        Group::new(name).unwrap()
    }

    fn params() -> NetworkParams {
        let mut params = NetworkParams::with_relay(
            alloc::vec![0xfd, 1, 2, 3, 4, 5, 6, 7],
            Some("aa@relay.example:443"),
            "casa.internal",
            604_800,
        )
        .unwrap();
        params.anchors = alloc::vec![DeviceId::from_bytes([3; 32]), DeviceId::from_bytes([9; 32])];
        params.policy = alloc::vec![Rule { from: group("sensori"), to: group("controller") }];
        params.excluded = alloc::vec![
            Excluded::new([100, 64, 9, 0], 24).unwrap(),
            Excluded::new([100, 64, 12, 7], 32).unwrap()
        ];
        params
    }

    /// An excluded block is `/10` to one address, aligned, and a list of them
    /// is sorted and without repeats, as every list a parameter holds.
    #[test]
    fn an_excluded_block_is_aligned_and_the_list_has_one_spelling() {
        assert_eq!("100.64.9.0/24".parse::<Excluded>(), Excluded::new([100, 64, 9, 0], 24));
        assert_eq!("10.0.0.7".parse::<Excluded>(), Excluded::new([10, 0, 0, 7], 32));
        assert!("100.64.9.1/24".parse::<Excluded>().is_err(), "host bits");
        assert!("10.0.0.0/9".parse::<Excluded>().is_err(), "wider than a block");
        let one = Excluded::new([10, 0, 0, 7], 32).unwrap();
        assert!(Parameter::excluded(alloc::vec![one, one]).is_err());
        assert!(Parameter::excluded(Vec::new()).is_err());
        let mut decoded = params();
        decoded.excluded.reverse();
        let sorted = params().with_excluded(decoded.excluded).unwrap();
        assert_eq!(sorted.excluded, params().excluded);
    }

    #[test]
    fn the_schemas_are_canonical() {
        assert!(is_canonical_schema(RULE_SCHEMA));
        assert!(is_canonical_schema(PARAMETER_NAMES));
    }

    #[test]
    fn every_leaf_round_trips_through_its_value_bytes() {
        for leaf in params().leaves() {
            let decoded = Parameter::decode(leaf.name(), &leaf.value_bytes()).unwrap();
            assert_eq!(decoded, leaf, "{}", leaf.name());
        }
    }

    #[test]
    fn parameters_round_trip_through_their_leaves() {
        let original = params();
        let rebuilt = NetworkParams::from_leaves(original.leaves()).unwrap();
        assert_eq!(rebuilt, original);
        assert_eq!(rebuilt.tree().root(), original.tree().root());
    }

    #[test]
    fn a_parameter_this_format_does_not_name_is_refused() {
        let mut writer = Writer::new();
        writer.u64(1);
        assert_eq!(Parameter::decode("colour", &writer.finish()), Err(Error::UnknownField));
    }

    #[test]
    fn defaults_have_no_leaf_and_no_second_spelling() {
        let mut plain = params();
        plain.anchors.clear();
        plain.policy.clear();
        let names: Vec<&str> = plain.leaves().iter().map(Parameter::name).collect();
        assert!(!names.contains(&"anchors"));
        assert!(!names.contains(&"policy"));
        assert!(!names.contains(&"ipv4"));

        let mut writer = Writer::new();
        writer.array(0);
        let empty = writer.finish();
        assert!(Parameter::decode("anchors", &empty).is_err());
        assert!(Parameter::decode("policy", &empty).is_err());
        assert!(Parameter::decode("relays", &empty).is_err());
    }

    #[test]
    fn a_second_relay_is_refused() {
        assert_eq!(
            Parameter::relays(alloc::vec!["a@x:1".into(), "b@y:2".into()]),
            Err(Error::InvalidValue("networks across several relays are not supported yet"))
        );
        let mut writer = Writer::new();
        writer.array(2).str("a@x:1").str("b@y:2");
        assert!(Parameter::decode("relays", &writer.finish()).is_err());
    }

    #[test]
    fn anchors_out_of_order_on_the_wire_are_refused() {
        let mut writer = Writer::new();
        writer.array(2);
        DeviceId::from_bytes([9; 32]).encode(&mut writer);
        DeviceId::from_bytes([3; 32]).encode(&mut writer);
        assert_eq!(Parameter::decode("anchors", &writer.finish()), Err(Error::NonCanonical));
    }

    #[test]
    fn too_many_anchors_are_refused() {
        let anchors = (0..=32_u8).map(|n| DeviceId::from_bytes([n; 32])).collect();
        assert_eq!(Parameter::anchors(anchors), Err(Error::LimitExceeded("anchors")));
    }

    #[test]
    fn a_window_of_zero_is_refused() {
        assert!(Parameter::window(0).is_err());
    }

    #[test]
    fn a_parameter_given_twice_is_refused() {
        let mut leaves = params().leaves();
        leaves.push(Parameter::Window(1));
        assert_eq!(NetworkParams::from_leaves(leaves), Err(Error::DuplicateKey));
    }

    #[test]
    fn changing_one_parameter_changes_only_its_leaf() {
        let before = params();
        let mut after = before.clone();
        after.policy.push(Rule { from: group("admin"), to: group("sensori") });
        after.policy.sort();
        let old = before.tree();
        let new = after.tree();
        assert_ne!(old.root(), new.root());
        let anchors = Parameter::position("anchors");
        assert_eq!(old.get(&anchors), new.get(&anchors));
    }
}

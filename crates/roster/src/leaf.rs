//! A device as the state tree holds it: its record and its settings, as one
//! leaf.
//!
//! The leaf is what a member presents to prove it belongs: the bytes here,
//! hashed, sit at the device's position in the state tree, and a proof against
//! a root shows they are the network's current word on that device. Everything
//! a peer needs to recognise the device is in it — keys, name, role, mode,
//! groups, and the address and relay an admin may have set.
//!
//! # Settings
//!
//! The settings are what an admin may change after admission, one field at a
//! time: whether the device is full or light, its groups, an assigned IPv4
//! address and a relay. None is optional in the encoding. An address or relay
//! not set is an empty byte string, which has one spelling, so one logical leaf
//! still has exactly one encoding.

use alloc::string::String;
use alloc::vec::Vec;

use crate::cbor::{Reader, Writer};
use crate::error::{Error, Result};
use crate::id::DeviceId;
use crate::limits;
use crate::merkle::Hash;
use crate::types::DeviceRecord;

/// The context a device's position in the state tree is derived under.
const POSITION_CONTEXT: &str = "peerfectly membership position v1";

/// The context a leaf's bytes are hashed under.
const DEVICE_LEAF_CONTEXT: &str = "peerfectly device leaf v1";

/// Canonical key order of a device's settings.
pub const DEVICE_SETTINGS_SCHEMA: &[&str] = &["ipv4", "mode", "relay", "groups"];

/// Canonical key order of a device leaf.
pub const DEVICE_LEAF_SCHEMA: &[&str] = &["record", "settings"];

/// Whether a member holds the network's state or relies on those that do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum Mode {
    /// Holds the roster state and the recent operations, and serves them.
    #[default]
    Full,
    /// Holds its own leaf and proof and one current root.
    Light,
}

impl Mode {
    /// The mode's encoded name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Light => "light",
        }
    }

    /// Reads a mode name, refusing any other.
    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "full" => Ok(Self::Full),
            "light" => Ok(Self::Light),
            _ => Err(Error::InvalidValue("mode")),
        }
    }
}

/// An access group's name, such as `sensori` or `controller`.
///
/// Lowercase ASCII letters, digits, `-` and `_`, from one to
/// [`limits::MAX_GROUP_LEN`] bytes. One spelling per group, so that a policy
/// rule and a device naming the same group always agree.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Group(String);

impl Group {
    /// Builds a group name, refusing anything outside the allowed spelling.
    pub fn new(text: impl Into<String>) -> Result<Self> {
        let text = text.into();
        if text.is_empty() {
            return Err(Error::InvalidValue("group name"));
        }
        if text.len() > limits::MAX_GROUP_LEN {
            return Err(Error::LimitExceeded("group name length"));
        }
        let allowed = |byte: u8| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        };
        if !text.bytes().all(allowed) {
            return Err(Error::InvalidValue("group name"));
        }
        Ok(Self(text))
    }

    /// The group's name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What an admin may change about a device after admitting it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceSettings {
    /// Full or light.
    pub mode: Mode,
    /// The groups it belongs to, sorted, without repeats.
    pub groups: Vec<Group>,
    /// An IPv4 address an admin assigned, if any.
    pub ipv4: Option<[u8; 4]>,
    /// The key of the relay it uses, if an admin set one.
    pub relay: Option<[u8; 32]>,
}

impl DeviceSettings {
    /// Builds settings, sorting the groups and refusing repeats and excess.
    pub fn new(
        mode: Mode,
        mut groups: Vec<Group>,
        ipv4: Option<[u8; 4]>,
        relay: Option<[u8; 32]>,
    ) -> Result<Self> {
        if groups.len() > limits::MAX_GROUPS_PER_DEVICE {
            return Err(Error::LimitExceeded("groups per device"));
        }
        groups.sort();
        if groups.windows(2).any(|pair| matches!(pair, [first, second] if first == second)) {
            return Err(Error::InvalidValue("repeated group"));
        }
        Ok(Self { mode, groups, ipv4, relay })
    }

    /// These settings with a change applied: each field the change sets is
    /// replaced, every other is kept.
    #[must_use]
    pub fn changed_by(&self, change: &SettingsChange) -> Self {
        let mut next = self.clone();
        if let Some(mode) = change.mode {
            next.mode = mode;
        }
        if let Some(groups) = &change.groups {
            next.groups.clone_from(groups);
        }
        if let Some(ipv4) = change.ipv4 {
            next.ipv4 = ipv4;
        }
        if let Some(relay) = change.relay {
            next.relay = relay;
        }
        next
    }

    /// Writes the settings.
    pub(crate) fn encode(&self, writer: &mut Writer) {
        writer.map(4);
        writer.key("ipv4").bytes(self.ipv4.as_ref().map_or(&[][..], |address| &address[..]));
        writer.key("mode").str(self.mode.as_str());
        writer.key("relay").bytes(self.relay.as_ref().map_or(&[][..], |key| &key[..]));
        writer.key("groups").array(self.groups.len() as u64);
        for group in &self.groups {
            writer.str(group.as_str());
        }
    }

    /// Reads settings, refusing groups out of order or repeated.
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let mut map = reader.map(DEVICE_SETTINGS_SCHEMA)?;
        let ipv4 = match map.key("ipv4")?.bytes(4, "ipv4 address")? {
            [] => None,
            [a, b, c, d] => Some([*a, *b, *c, *d]),
            _ => return Err(Error::InvalidValue("ipv4 address length")),
        };
        let mode = Mode::parse(map.key("mode")?.str(limits::MAX_MAP_KEY_LEN, "mode")?)?;
        let relay = match map.key("relay")?.bytes(32, "relay key")? {
            [] => None,
            bytes => Some(
                <[u8; 32]>::try_from(bytes).map_err(|_| Error::InvalidValue("relay key length"))?,
            ),
        };
        let reader = map.key("groups")?;
        let count = reader.array(limits::MAX_GROUPS_PER_DEVICE, "groups per device")?;
        let mut groups = Vec::with_capacity(count);
        for _ in 0..count {
            groups.push(Group::new(reader.str(limits::MAX_GROUP_LEN, "group name length")?)?);
        }
        map.finish()?;
        // Sorted and unique on the wire too: a second order would be a second
        // encoding of the same settings.
        if groups.windows(2).any(|pair| matches!(pair, [first, second] if first >= second)) {
            return Err(Error::NonCanonical);
        }
        Ok(Self { mode, groups, ipv4, relay })
    }
}

/// Canonical key order of a settings change.
pub const SETTINGS_CHANGE_SCHEMA: &[&str] = &["ipv4", "mode", "relay", "device", "groups"];

/// What a `set_device` operation changes: each field is either left alone or
/// set, and resolves on its own.
///
/// Each field is encoded as an array of nothing (left alone) or of one value
/// (set), so "left alone" and "set to nothing" are different values with one
/// spelling each: clearing an assigned address is setting it to an empty one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SettingsChange {
    /// A new mode, if this changes it.
    pub mode: Option<Mode>,
    /// A new set of groups, if this changes them.
    pub groups: Option<Vec<Group>>,
    /// A new assigned address, or its removal, if this changes it.
    pub ipv4: Option<Option<[u8; 4]>>,
    /// A new relay, or its removal, if this changes it.
    pub relay: Option<Option<[u8; 32]>>,
}

impl SettingsChange {
    /// Whether the change leaves every field alone.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.mode.is_none() && self.groups.is_none() && self.ipv4.is_none() && self.relay.is_none()
    }

    /// The change split into one change per field it sets, each numbered, so
    /// that each field can be resolved on its own.
    #[must_use]
    pub fn fields(&self) -> Vec<(u8, Self)> {
        let mut fields = Vec::new();
        if let Some(mode) = self.mode {
            fields.push((0, Self { mode: Some(mode), ..Self::default() }));
        }
        if let Some(groups) = &self.groups {
            fields.push((1, Self { groups: Some(groups.clone()), ..Self::default() }));
        }
        if let Some(ipv4) = self.ipv4 {
            fields.push((2, Self { ipv4: Some(ipv4), ..Self::default() }));
        }
        if let Some(relay) = self.relay {
            fields.push((3, Self { relay: Some(relay), ..Self::default() }));
        }
        fields
    }

    /// Writes the change, after the device it names.
    pub(crate) fn encode(&self, device: &DeviceId, writer: &mut Writer) {
        writer.map(5);
        writer.key("ipv4");
        match &self.ipv4 {
            None => {
                writer.array(0);
            }
            Some(address) => {
                writer.array(1);
                writer.bytes(address.as_ref().map_or(&[][..], |address| &address[..]));
            }
        }
        writer.key("mode");
        match self.mode {
            None => {
                writer.array(0);
            }
            Some(mode) => {
                writer.array(1).str(mode.as_str());
            }
        }
        writer.key("relay");
        match &self.relay {
            None => {
                writer.array(0);
            }
            Some(relay) => {
                writer.array(1);
                writer.bytes(relay.as_ref().map_or(&[][..], |key| &key[..]));
            }
        }
        writer.key("device");
        device.encode(writer);
        writer.key("groups");
        match &self.groups {
            None => {
                writer.array(0);
            }
            Some(groups) => {
                writer.array(1).array(groups.len() as u64);
                for group in groups {
                    writer.str(group.as_str());
                }
            }
        }
    }

    /// Reads a change and the device it names, refusing one that changes
    /// nothing.
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<(DeviceId, Self)> {
        let mut map = reader.map(SETTINGS_CHANGE_SCHEMA)?;
        let value = map.key("ipv4")?;
        let ipv4 = match value.array(1, "ipv4")? {
            0 => None,
            _ => Some(match value.bytes(4, "ipv4 address")? {
                [] => None,
                [a, b, c, d] => Some([*a, *b, *c, *d]),
                _ => return Err(Error::InvalidValue("ipv4 address length")),
            }),
        };
        let value = map.key("mode")?;
        let mode = match value.array(1, "mode")? {
            0 => None,
            _ => Some(Mode::parse(value.str(limits::MAX_MAP_KEY_LEN, "mode")?)?),
        };
        let value = map.key("relay")?;
        let relay = match value.array(1, "relay")? {
            0 => None,
            _ => Some(match value.bytes(32, "relay key")? {
                [] => None,
                bytes => Some(
                    <[u8; 32]>::try_from(bytes)
                        .map_err(|_| Error::InvalidValue("relay key length"))?,
                ),
            }),
        };
        let device = DeviceId::decode(map.key("device")?)?;
        let value = map.key("groups")?;
        let groups = match value.array(1, "groups")? {
            0 => None,
            _ => {
                let count = value.array(limits::MAX_GROUPS_PER_DEVICE, "groups per device")?;
                let mut groups = Vec::with_capacity(count);
                for _ in 0..count {
                    groups
                        .push(Group::new(value.str(limits::MAX_GROUP_LEN, "group name length")?)?);
                }
                if groups.windows(2).any(|pair| matches!(pair, [first, second] if first >= second))
                {
                    return Err(Error::NonCanonical);
                }
                Some(groups)
            }
        };
        map.finish()?;
        let change = Self { mode, groups, ipv4, relay };
        if change.is_empty() {
            return Err(Error::InvalidValue("a settings change that changes nothing"));
        }
        Ok((device, change))
    }
}

/// A device as the state tree holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLeaf {
    /// Who the device is and how it was admitted.
    pub record: DeviceRecord,
    /// What an admin has set about it since.
    pub settings: DeviceSettings,
}

/// A leaf reads as its record: who the device is, which is what nearly every
/// question about a member asks. Its settings are asked for by name.
impl core::ops::Deref for DeviceLeaf {
    type Target = DeviceRecord;

    fn deref(&self) -> &DeviceRecord {
        &self.record
    }
}

impl DeviceLeaf {
    /// Where the device's leaf sits in the state tree.
    #[must_use]
    pub fn position(device: &DeviceId) -> Hash {
        blake3::derive_key(POSITION_CONTEXT, device.as_bytes())
    }

    /// The hash the state tree holds for this leaf.
    #[must_use]
    pub fn value_hash(&self) -> Hash {
        blake3::derive_key(DEVICE_LEAF_CONTEXT, &self.to_bytes())
    }

    /// The leaf's canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.encode(&mut writer);
        writer.finish()
    }

    /// Reads a leaf from its canonical bytes, refusing anything else.
    pub fn from_bytes(input: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(input);
        let leaf = Self::decode(&mut reader)?;
        reader.finish()?;
        Ok(leaf)
    }

    pub(crate) fn encode(&self, writer: &mut Writer) {
        writer.map(2);
        writer.key("record");
        self.record.encode(writer);
        writer.key("settings");
        self.settings.encode(writer);
    }

    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let mut map = reader.map(DEVICE_LEAF_SCHEMA)?;
        let record = DeviceRecord::decode(map.key("record")?)?;
        let settings = DeviceSettings::decode(map.key("settings")?)?;
        map.finish()?;
        Ok(Self { record, settings })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use crate::cbor::is_canonical_schema;
    use crate::id::OperationId;
    use crate::sign::{Ed25519Signer, Signer};
    use crate::types::{Algorithm, KeyEntry, KeyPurpose, Role};

    fn record() -> DeviceRecord {
        let signing = KeyEntry::new(
            Algorithm::Ed25519,
            KeyPurpose::Signing,
            Ed25519Signer::from_seed([1; 32]).public_key().as_bytes().to_vec(),
        )
        .unwrap();
        let attestation = KeyEntry::new(
            Algorithm::Ed25519,
            KeyPurpose::Attestation,
            Ed25519Signer::from_seed([2; 32]).public_key().as_bytes().to_vec(),
        )
        .unwrap();
        let mut keys = vec![signing.clone(), attestation];
        keys.sort_by_key(KeyEntry::order_key);
        DeviceRecord {
            id: DeviceId::of_signing_key(&signing.value),
            keys,
            name: "sensore-1".into(),
            role: Role::Member,
            founder: false,
            added_by: OperationId::from_bytes([7; 32]),
            capabilities: vec![],
        }
    }

    fn leaf(settings: DeviceSettings) -> DeviceLeaf {
        DeviceLeaf { record: record(), settings }
    }

    fn groups(names: &[&str]) -> Vec<Group> {
        names.iter().map(|name| Group::new(*name).unwrap()).collect()
    }

    #[test]
    fn the_schemas_are_in_canonical_order() {
        assert!(is_canonical_schema(DEVICE_SETTINGS_SCHEMA));
        assert!(is_canonical_schema(DEVICE_LEAF_SCHEMA));
    }

    #[test]
    fn a_leaf_round_trips_through_its_bytes() {
        let settings = DeviceSettings::new(
            Mode::Light,
            groups(&["sensori", "lab"]),
            Some([100, 70, 0, 9]),
            Some([5; 32]),
        )
        .unwrap();
        let original = leaf(settings);
        let bytes = original.to_bytes();
        let decoded = DeviceLeaf::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.to_bytes(), bytes);
    }

    #[test]
    fn default_settings_round_trip_with_nothing_set() {
        let original = leaf(DeviceSettings::default());
        let decoded = DeviceLeaf::from_bytes(&original.to_bytes()).unwrap();
        assert_eq!(decoded.settings.mode, Mode::Full);
        assert_eq!(decoded.settings.ipv4, None);
        assert_eq!(decoded.settings.relay, None);
        assert!(decoded.settings.groups.is_empty());
    }

    #[test]
    fn groups_are_sorted_and_repeats_refused() {
        let settings =
            DeviceSettings::new(Mode::Full, groups(&["zeta", "alpha"]), None, None).unwrap();
        assert_eq!(settings.groups, groups(&["alpha", "zeta"]));
        assert_eq!(
            DeviceSettings::new(Mode::Full, groups(&["a", "a"]), None, None),
            Err(Error::InvalidValue("repeated group"))
        );
    }

    #[test]
    fn a_group_name_has_one_spelling() {
        assert!(Group::new("sensori-2_b").is_ok());
        assert_eq!(Group::new("Sensori"), Err(Error::InvalidValue("group name")));
        assert_eq!(Group::new(""), Err(Error::InvalidValue("group name")));
        assert_eq!(Group::new("a b"), Err(Error::InvalidValue("group name")));
        assert_eq!(Group::new("x".repeat(33)), Err(Error::LimitExceeded("group name length")));
    }

    #[test]
    fn groups_out_of_order_on_the_wire_are_refused() {
        let mut writer = Writer::new();
        writer.map(2);
        writer.key("record");
        record().encode(&mut writer);
        writer.key("settings").map(4);
        writer.key("ipv4").bytes(&[]);
        writer.key("mode").str("full");
        writer.key("relay").bytes(&[]);
        writer.key("groups").array(2);
        writer.str("zeta").str("alpha");
        assert_eq!(DeviceLeaf::from_bytes(&writer.finish()), Err(Error::NonCanonical));
    }

    #[test]
    fn an_address_of_the_wrong_length_is_refused() {
        let mut writer = Writer::new();
        writer.map(4);
        writer.key("ipv4").bytes(&[10, 0, 0]);
        writer.key("mode").str("full");
        writer.key("relay").bytes(&[]);
        writer.key("groups").array(0);
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes);
        assert_eq!(
            DeviceSettings::decode(&mut reader),
            Err(Error::InvalidValue("ipv4 address length"))
        );
    }

    fn change_round_trip(change: &SettingsChange) -> Result<(DeviceId, SettingsChange)> {
        let mut writer = Writer::new();
        change.encode(&DeviceId::from_bytes([4; 32]), &mut writer);
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes);
        SettingsChange::decode(&mut reader)
    }

    #[test]
    fn a_settings_change_round_trips_and_clearing_differs_from_leaving_alone() {
        assert!(is_canonical_schema(SETTINGS_CHANGE_SCHEMA));
        let clear = SettingsChange { ipv4: Some(None), ..SettingsChange::default() };
        let set = SettingsChange {
            mode: Some(Mode::Light),
            groups: Some(groups(&["a", "b"])),
            ipv4: Some(Some([10, 0, 0, 9])),
            relay: Some(Some([3; 32])),
        };
        for change in [&clear, &set] {
            let (device, decoded) = change_round_trip(change).unwrap();
            assert_eq!(device, DeviceId::from_bytes([4; 32]));
            assert_eq!(&decoded, change);
        }
        let settings = DeviceSettings::new(Mode::Full, vec![], Some([10, 0, 0, 1]), None).unwrap();
        assert_eq!(settings.changed_by(&clear).ipv4, None);
        assert_eq!(settings.changed_by(&set).mode, Mode::Light);
        assert_eq!(settings.changed_by(&clear).mode, Mode::Full, "a field left alone is kept");
    }

    #[test]
    fn a_change_that_changes_nothing_is_refused() {
        assert_eq!(
            change_round_trip(&SettingsChange::default()),
            Err(Error::InvalidValue("a settings change that changes nothing"))
        );
    }

    #[test]
    fn an_unknown_mode_is_refused() {
        assert_eq!(Mode::parse("partial"), Err(Error::InvalidValue("mode")));
    }

    #[test]
    fn a_settings_change_changes_the_leaf_hash() {
        let full = leaf(DeviceSettings::default());
        let light = leaf(DeviceSettings::new(Mode::Light, vec![], None, None).unwrap());
        assert_ne!(full.value_hash(), light.value_hash());
    }

    #[test]
    fn the_position_depends_on_the_device_alone() {
        let device = record().id;
        assert_eq!(DeviceLeaf::position(&device), DeviceLeaf::position(&device));
        assert_ne!(
            DeviceLeaf::position(&device),
            DeviceLeaf::position(&DeviceId::from_bytes([9; 32]))
        );
    }
}

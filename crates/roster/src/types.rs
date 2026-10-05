//! The seven operation types, the structures they carry, and their canonical
//! codecs.
//!
//! # Shape of an operation on the wire
//!
//! ```text
//! Operation = { "id": bstr(32), "sig": bstr(64), "core": bstr }
//! Core      = { "ts": uint, "alg": tstr, "body": bstr, "type": tstr,
//!               "author": bstr(32), "network": bstr(32),
//!               "parents": [ bstr(32) ... ] }
//! ```
//!
//! Two things are embedded as byte strings rather than nested maps, for the
//! same reason both times: the bytes a signature covers must be handed back as
//! a slice of exactly what arrived.
//!
//! * `core` is the signed and hashed region. Holding it as a byte string means
//!   verification never re-encodes anything.
//! * `body` is decoded only once `type` is known. Canonical key order puts
//!   `body` before `type`, so a body decoded in place would have to be parsed
//!   before the schema that governs it was known.
//!
//! # Nothing here is optional, with one exception
//!
//! Every field is required, including the booleans. An optional field would
//! give one logical value two encodings — one omitting it, one spelling out
//! the default — and therefore two operation ids for one operation. That is
//! the fork this format exists to prevent.
//!
//! The exception is the network's IPv4 range, `ipv4` in [`NetworkParams`]. It
//! arrived after networks already existed, and writing it always would have
//! changed the bytes, and so the id, of every operation that carries
//! parameters. Absence still has exactly one spelling — the key is not written
//! — and a key written with an empty value is refused rather than read as
//! absence.

use crate::cbor::{Reader, Writer};
use crate::error::{Error, Result};
use crate::id::{DeviceId, KeyId, NetworkId, OperationId};
use crate::limits;

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

/// Field names of the wire operation, in canonical order.
pub const OPERATION_SCHEMA: &[&str] = &["id", "sig", "core"];
/// Field names of the signed core, in canonical order.
pub const CORE_SCHEMA: &[&str] = &["ts", "alg", "body", "type", "author", "network", "parents"];
/// Field names of a key entry, in canonical order.
pub const KEY_ENTRY_SCHEMA: &[&str] = &["alg", "value", "purpose"];
/// Field names of a device specification, in canonical order.
pub const DEVICE_SPEC_SCHEMA: &[&str] = &["keys", "name", "role", "founder", "capabilities"];
/// Field names of a derived device record, in canonical order.
pub const DEVICE_RECORD_SCHEMA: &[&str] =
    &["id", "keys", "name", "role", "founder", "added_by", "capabilities"];
/// Field names of the network parameters, in canonical order.
///
/// `ipv4` and `leaving` may be absent: see [`NETWORK_PARAMS_OPTIONAL`].
pub const NETWORK_PARAMS_SCHEMA: &[&str] =
    &["ula", "ipv4", "relay", "suffix", "leaving", "relay_cert", "rendezvous", "snapshot_window"];
/// The keys of the network parameters that may be absent.
///
/// Each is left out when absent rather than written empty, so that parameters
/// without it encode exactly as they did before it existed.
pub const NETWORK_PARAMS_OPTIONAL: &[&str] = &["ipv4", "leaving"];
/// Field names of a relay being left, in canonical order.
pub const LEAVING_SCHEMA: &[&str] = &["relay", "until", "relay_cert"];
/// Field names of a `create_network` body, in canonical order.
pub const CREATE_NETWORK_SCHEMA: &[&str] = &["device", "params"];
/// Field names of a `revoke_device` body, in canonical order.
pub const REVOKE_DEVICE_SCHEMA: &[&str] = &["device", "reason"];
/// Field names of a `promote` body, in canonical order.
pub const PROMOTE_SCHEMA: &[&str] = &["device", "founder"];
/// Field names of a `demote` body, in canonical order.
pub const DEMOTE_SCHEMA: &[&str] = &["device"];
/// Field names of a `rename` body, in canonical order.
pub const RENAME_SCHEMA: &[&str] = &["name", "device"];

/// Every schema in the format, in canonical key order.
///
/// Public so that a second implementation can assert its own field order
/// against this one instead of transcribing `FORMAT.md` by eye.
pub const ALL_SCHEMAS: &[&[&str]] = &[
    OPERATION_SCHEMA,
    CORE_SCHEMA,
    KEY_ENTRY_SCHEMA,
    DEVICE_SPEC_SCHEMA,
    DEVICE_RECORD_SCHEMA,
    NETWORK_PARAMS_SCHEMA,
    LEAVING_SCHEMA,
    CREATE_NETWORK_SCHEMA,
    REVOKE_DEVICE_SCHEMA,
    PROMOTE_SCHEMA,
    DEMOTE_SCHEMA,
    RENAME_SCHEMA,
];

// ---------------------------------------------------------------------------
// Enumerated values
// ---------------------------------------------------------------------------

/// A signature algorithm.
///
/// The roster carries more than one from the first version because the root
/// key lives in a phone's secure enclave, which dictates P-256, while device
/// signing and transport keys are ed25519. An algorithm this build does not
/// know is an error, never something to pass over: the operation it cannot
/// read might be a revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Algorithm {
    /// Ed25519, under the strict verification profile.
    Ed25519,
    /// ECDSA over NIST P-256, with `s` required to be in low form.
    P256,
}

impl Algorithm {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::P256 => "p256",
        }
    }

    /// Parses a wire name.
    ///
    /// The exhaustive match is what makes an unhandled algorithm a compile
    /// error in this crate and an explicit rejection at run time, rather than
    /// a silently skipped operation.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "ed25519" => Ok(Self::Ed25519),
            "p256" => Ok(Self::P256),
            _ => Err(Error::UnknownAlgorithm),
        }
    }

    /// Length in bytes of a public key under this algorithm.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        match self {
            // Compressed Edwards y-coordinate.
            Self::Ed25519 => 32,
            // SEC1 compressed point.
            Self::P256 => 33,
        }
    }
}

/// What a key in a device record is for.
///
/// The purposes are separate because the key that signs roster operations, the
/// key that establishes transport sessions and the key that dates a roster must
/// be different values. Reusing one key across two protocols invites
/// cross-protocol attacks, where a signature produced in one context is
/// meaningful in the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyPurpose {
    /// Signs roster operations.
    Signing,
    /// Establishes transport sessions; the iroh `NodeId`.
    Transport,
    /// Signs attestations, which date a roster and describe none.
    ///
    /// Separate from [`Self::Signing`] for a reason the other two do not share:
    /// it is the key a device may use with **nobody present**. A phone raises a
    /// lock prompt for every signature, so a key that both dated a roster
    /// unattended and signed operations would hand the unattended property to
    /// the signing power. What this key can express is bounded by the
    /// attestation carrying no state; what it may be used for is bounded by its
    /// being a different key.
    Attestation,
}

impl KeyPurpose {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signing => "signing",
            Self::Transport => "transport",
            Self::Attestation => "attestation",
        }
    }

    /// Parses a wire name.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "signing" => Ok(Self::Signing),
            "transport" => Ok(Self::Transport),
            "attestation" => Ok(Self::Attestation),
            _ => Err(Error::InvalidValue("purpose")),
        }
    }
}

/// A device's authority in the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// May author operations.
    Admin,
    /// May participate, but not author operations.
    Member,
}

impl Role {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }

    /// Parses a wire name.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "admin" => Ok(Self::Admin),
            "member" => Ok(Self::Member),
            _ => Err(Error::InvalidValue("role")),
        }
    }
}

/// One of the seven operation types.
///
/// The set is closed. Every new type would have to be multiplied against the
/// conflict rules of every existing one, so adding an eighth is a decision
/// about the merge semantics of the whole roster, not an additive change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperationType {
    /// Establishes the network and its founding admin.
    CreateNetwork,
    /// Adds a device with its keys, name, role, and capabilities.
    AddDevice,
    /// Revokes a device. Definitive: there is no undo, only a new key.
    RevokeDevice,
    /// Raises a device to admin.
    Promote,
    /// Lowers a device to member.
    Demote,
    /// Changes a device's name.
    Rename,
    /// Changes the network parameters.
    SetNetwork,
}

impl OperationType {
    /// Every type, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::CreateNetwork,
        Self::AddDevice,
        Self::RevokeDevice,
        Self::Promote,
        Self::Demote,
        Self::Rename,
        Self::SetNetwork,
    ];

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateNetwork => "create_network",
            Self::AddDevice => "add_device",
            Self::RevokeDevice => "revoke_device",
            Self::Promote => "promote",
            Self::Demote => "demote",
            Self::Rename => "rename",
            Self::SetNetwork => "set_network",
        }
    }

    /// Parses a wire name, rejecting anything outside the closed set.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "create_network" => Ok(Self::CreateNetwork),
            "add_device" => Ok(Self::AddDevice),
            "revoke_device" => Ok(Self::RevokeDevice),
            "promote" => Ok(Self::Promote),
            "demote" => Ok(Self::Demote),
            "rename" => Ok(Self::Rename),
            "set_network" => Ok(Self::SetNetwork),
            _ => Err(Error::UnknownOperationType),
        }
    }
}

// ---------------------------------------------------------------------------
// Key entries and devices
// ---------------------------------------------------------------------------

/// One public key held by a device, with its purpose and algorithm stated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyEntry {
    /// The algorithm this key belongs to.
    pub alg: Algorithm,
    /// The public key bytes.
    pub value: Vec<u8>,
    /// What the key is used for.
    pub purpose: KeyPurpose,
}

impl KeyEntry {
    /// Builds a key entry, checking the value's length against its algorithm.
    pub fn new(alg: Algorithm, purpose: KeyPurpose, value: Vec<u8>) -> Result<Self> {
        if value.len() != alg.public_key_len() {
            return Err(Error::IdentifierLength);
        }
        Ok(Self { alg, value, purpose })
    }

    /// This key's id.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        KeyId::of_public_key(&self.value)
    }

    /// Writes the entry.
    pub(crate) fn encode(&self, writer: &mut Writer) {
        writer.map(3);
        writer.key("alg").str(self.alg.as_str());
        writer.key("value").bytes(&self.value);
        writer.key("purpose").str(self.purpose.as_str());
    }

    /// Reads an entry.
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let mut map = reader.map(KEY_ENTRY_SCHEMA)?;
        let alg = Algorithm::parse(map.key("alg")?.str(limits::MAX_MAP_KEY_LEN, "alg")?)?;
        let value =
            map.key("value")?.bytes(limits::MAX_PUBLIC_KEY_LEN, "public key length")?.to_vec();
        let purpose =
            KeyPurpose::parse(map.key("purpose")?.str(limits::MAX_MAP_KEY_LEN, "purpose")?)?;
        map.finish()?;
        Self::new(alg, purpose, value)
    }

    /// The entry's canonical bytes, which are also how entries are ordered.
    ///
    /// Public because the order is *required* of anyone building a device: a
    /// caller with no way to compute it has to guess at this encoding, and an
    /// approximation that happens to agree for two keys of one length silently
    /// disagrees the moment a P-256 key (33 bytes) sits beside an ed25519 one
    /// (32). One definition, exported, rather than a second one guessed at.
    #[must_use]
    pub fn order_key(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.encode(&mut writer);
        writer.finish()
    }
}

/// Checks a device's key list: bounded, canonically ordered, no reused key
/// value, and at least one key of each of the signing and attestation purposes.
///
/// The ordering requirement is not tidiness. An unordered list would let the
/// same key set encode two ways, which is two device records and two ids for
/// one device.
fn validate_keys(keys: &[KeyEntry]) -> Result<()> {
    if keys.is_empty() {
        return Err(Error::MissingSigningKey);
    }
    if keys.len() > limits::MAX_KEYS_PER_DEVICE {
        return Err(Error::LimitExceeded("keys per device"));
    }

    let mut previous: Option<Vec<u8>> = None;
    for entry in keys {
        let current = entry.order_key();
        if let Some(prior) = &previous {
            match prior.as_slice().cmp(current.as_slice()) {
                core::cmp::Ordering::Less => {}
                core::cmp::Ordering::Equal => return Err(Error::DuplicateKey),
                core::cmp::Ordering::Greater => return Err(Error::KeyOrdering),
            }
        }
        previous = Some(current);
    }

    // A key value may appear once and once only. This is what enforces the
    // rule that a device's signing key and transport key are different keys:
    // one value serving two protocols is a cross-protocol attack waiting for
    // someone to notice.
    for (index, entry) in keys.iter().enumerate() {
        if keys.iter().skip(index.saturating_add(1)).any(|other| other.value == entry.value) {
            return Err(Error::KeyReuse);
        }
    }

    if !keys.iter().any(|entry| entry.purpose == KeyPurpose::Signing) {
        return Err(Error::MissingSigningKey);
    }
    // A device that cannot date the roster it belongs to would leave every other
    // device measuring its freshness against a device that never speaks, which
    // is the defect this key exists to close. Required here rather than checked
    // where freshness is read: a record without one is not a device this network
    // can contain.
    if !keys.iter().any(|entry| entry.purpose == KeyPurpose::Attestation) {
        return Err(Error::MissingAttestationKey);
    }
    Ok(())
}

/// The identifying signing key of a key list.
///
/// The first signing entry in canonical order. A device's key set never
/// changes — none of the seven operations adds a key to an existing device —
/// so this is fixed for the device's lifetime.
fn identifying_key(keys: &[KeyEntry]) -> Result<&KeyEntry> {
    keys.iter().find(|entry| entry.purpose == KeyPurpose::Signing).ok_or(Error::MissingSigningKey)
}

/// A capability string, such as `serves` or `lan_exit:192.168.1.0/24`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capability(String);

impl Capability {
    /// Builds a capability, checking its length.
    pub fn new(text: impl Into<String>) -> Result<Self> {
        let text = text.into();
        if text.len() > limits::MAX_CAPABILITY_LEN {
            return Err(Error::LimitExceeded("capability length"));
        }
        Ok(Self(text))
    }

    /// The capability text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A device as an operation describes it.
///
/// This is what appears in an operation body. It has no id and no `added_by`:
/// both are derived, and `added_by` would be the enclosing operation's own id,
/// which cannot be known before that operation is encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSpec {
    /// Public keys, in canonical order.
    pub keys: Vec<KeyEntry>,
    /// Human-readable name.
    pub name: String,
    /// Authority in the network.
    pub role: Role,
    /// Whether this device is a founder.
    ///
    /// A founder may be revoked or demoted only by itself. The rule is
    /// enforced where authority is derived, not here: this crate has no
    /// roster state and so cannot know whether a target is a founder.
    pub founder: bool,
    /// Declared capabilities.
    pub capabilities: Vec<Capability>,
}

impl DeviceSpec {
    /// Builds a device specification, checking every bound and the key rules.
    pub fn new(
        keys: Vec<KeyEntry>,
        name: impl Into<String>,
        role: Role,
        founder: bool,
        capabilities: Vec<Capability>,
    ) -> Result<Self> {
        let name = name.into();
        validate_keys(&keys)?;
        if name.len() > limits::MAX_NAME_LEN {
            return Err(Error::LimitExceeded("device name length"));
        }
        if capabilities.len() > limits::MAX_CAPABILITIES {
            return Err(Error::LimitExceeded("capability count"));
        }
        Ok(Self { keys, name, role, founder, capabilities })
    }

    /// The device's id, derived from its identifying signing key.
    pub fn device_id(&self) -> Result<DeviceId> {
        Ok(DeviceId::of_signing_key(&identifying_key(&self.keys)?.value))
    }

    /// Turns the specification into the record derived state would hold.
    pub fn into_record(self, added_by: OperationId) -> Result<DeviceRecord> {
        let id = self.device_id()?;
        Ok(DeviceRecord {
            id,
            keys: self.keys,
            name: self.name,
            role: self.role,
            founder: self.founder,
            added_by,
            capabilities: self.capabilities,
        })
    }

    /// Writes the specification.
    pub(crate) fn encode(&self, writer: &mut Writer) {
        writer.map(5);
        writer.key("keys").array(self.keys.len() as u64);
        for entry in &self.keys {
            entry.encode(writer);
        }
        writer.key("name").str(&self.name);
        writer.key("role").str(self.role.as_str());
        writer.key("founder").bool(self.founder);
        writer.key("capabilities").array(self.capabilities.len() as u64);
        for capability in &self.capabilities {
            writer.str(capability.as_str());
        }
    }

    /// Reads a specification.
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let mut map = reader.map(DEVICE_SPEC_SCHEMA)?;
        let keys = decode_keys(map.key("keys")?)?;
        let name = map.key("name")?.str(limits::MAX_NAME_LEN, "device name length")?.to_owned();
        let role = Role::parse(map.key("role")?.str(limits::MAX_MAP_KEY_LEN, "role")?)?;
        let founder = map.key("founder")?.bool()?;
        let capabilities = decode_capabilities(map.key("capabilities")?)?;
        map.finish()?;
        Self::new(keys, name, role, founder, capabilities)
    }
}

/// Reads a device's key list.
fn decode_keys(reader: &mut Reader<'_>) -> Result<Vec<KeyEntry>> {
    let count = reader.array(limits::MAX_KEYS_PER_DEVICE, "keys per device")?;
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        keys.push(KeyEntry::decode(reader)?);
    }
    Ok(keys)
}

/// Reads a capability list.
fn decode_capabilities(reader: &mut Reader<'_>) -> Result<Vec<Capability>> {
    let count = reader.array(limits::MAX_CAPABILITIES, "capability count")?;
    let mut capabilities = Vec::with_capacity(count);
    for _ in 0..count {
        let text = reader.str(limits::MAX_CAPABILITY_LEN, "capability length")?;
        capabilities.push(Capability::new(text)?);
    }
    Ok(capabilities)
}

/// A device as derived state holds it: the specification plus the identity and
/// provenance that are computed rather than stated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    /// The device's id.
    pub id: DeviceId,
    /// Public keys, in canonical order.
    pub keys: Vec<KeyEntry>,
    /// Human-readable name.
    pub name: String,
    /// Authority in the network.
    pub role: Role,
    /// Whether this device is a founder.
    pub founder: bool,
    /// The operation that added this device.
    pub added_by: OperationId,
    /// Declared capabilities.
    pub capabilities: Vec<Capability>,
}

impl DeviceRecord {
    /// The record's canonical bytes.
    ///
    /// Derived state and snapshots are built on this type, so its encoding is
    /// pinned here alongside everything else rather than being invented later.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.encode(&mut writer);
        writer.finish()
    }

    /// Reads a record from its canonical bytes.
    pub fn from_bytes(input: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(input);
        let record = Self::decode(&mut reader)?;
        reader.finish()?;
        Ok(record)
    }

    /// Writes the record.
    pub(crate) fn encode(&self, writer: &mut Writer) {
        writer.map(7);
        writer.key("id");
        self.id.encode(writer);
        writer.key("keys").array(self.keys.len() as u64);
        for entry in &self.keys {
            entry.encode(writer);
        }
        writer.key("name").str(&self.name);
        writer.key("role").str(self.role.as_str());
        writer.key("founder").bool(self.founder);
        writer.key("added_by");
        self.added_by.encode(writer);
        writer.key("capabilities").array(self.capabilities.len() as u64);
        for capability in &self.capabilities {
            writer.str(capability.as_str());
        }
    }

    /// Reads a record, checking that the stated id matches the keys.
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let mut map = reader.map(DEVICE_RECORD_SCHEMA)?;
        let id = DeviceId::decode(map.key("id")?)?;
        let keys = decode_keys(map.key("keys")?)?;
        let name = map.key("name")?.str(limits::MAX_NAME_LEN, "device name length")?.to_owned();
        let role = Role::parse(map.key("role")?.str(limits::MAX_MAP_KEY_LEN, "role")?)?;
        let founder = map.key("founder")?.bool()?;
        let added_by = OperationId::decode(map.key("added_by")?)?;
        let capabilities = decode_capabilities(map.key("capabilities")?)?;
        map.finish()?;

        validate_keys(&keys)?;
        if name.len() > limits::MAX_NAME_LEN {
            return Err(Error::LimitExceeded("device name length"));
        }
        // The id is stated and also derivable. Checking turns an encoder bug
        // into a loud rejection rather than a device whose id disagrees with
        // its own key.
        if DeviceId::of_signing_key(&identifying_key(&keys)?.value) != id {
            return Err(Error::IdMismatch);
        }
        Ok(Self { id, keys, name, role, founder, added_by, capabilities })
    }
}

// ---------------------------------------------------------------------------
// IPv4 range
// ---------------------------------------------------------------------------

/// The encoded length of an IPv4 range: four address bytes, then the prefix
/// length.
pub const IPV4_RANGE_LEN: usize = 5;

/// The blocks a range must lie inside, as address and prefix length.
///
/// The RFC 1918 private blocks, the shared address space of RFC 6598 and the
/// benchmarking block of RFC 2544. Everything outside them is either public —
/// a range there would route real hosts into the tunnel — or reserved with a
/// meaning of its own: loopback, link-local, multicast, `0.0.0.0/8`,
/// `240.0.0.0/4`.
pub const IPV4_RANGE_BLOCKS: [([u8; 4], u8); 5] = [
    ([10, 0, 0, 0], 8),
    ([172, 16, 0, 0], 12),
    ([192, 168, 0, 0], 16),
    ([100, 64, 0, 0], 10),
    ([198, 18, 0, 0], 15),
];

/// The IPv4 range a network's devices derive their addresses in.
///
/// Canonical by construction: no host bits, a prefix length from
/// [`Self::MIN_PREFIX_LEN`] to [`Self::MAX_PREFIX_LEN`], inside one of
/// [`IPV4_RANGE_BLOCKS`]. A value of this type that exists is one that is
/// allowed, so nothing downstream checks it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Range {
    address: [u8; 4],
    prefix_len: u8,
}

impl Ipv4Range {
    /// The widest range allowed. Wider would swallow whole private blocks a
    /// home or office network is likely to be using.
    pub const MIN_PREFIX_LEN: u8 = 8;
    /// The narrowest range allowed: sixteen addresses, fourteen of them
    /// assignable. Narrower holds too few devices for the derivation to find
    /// room.
    pub const MAX_PREFIX_LEN: u8 = 28;
    /// The range of a network whose parameters carry none.
    pub const DEFAULT: Self = Self { address: [100, 64, 0, 0], prefix_len: 10 };

    /// Builds a range, refusing any that is not allowed.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidValue`] naming the rule: the prefix length, host bits
    /// set, or a range outside the allowed blocks.
    pub fn new(address: [u8; 4], prefix_len: u8) -> Result<Self> {
        if !(Self::MIN_PREFIX_LEN..=Self::MAX_PREFIX_LEN).contains(&prefix_len) {
            return Err(Error::InvalidValue("ipv4 range prefix length"));
        }
        let bits = u32::from_be_bytes(address);
        if bits & !mask(prefix_len) != 0 {
            return Err(Error::InvalidValue("ipv4 range has host bits set"));
        }
        let inside = IPV4_RANGE_BLOCKS.iter().any(|(block, block_len)| {
            prefix_len >= *block_len && bits & mask(*block_len) == u32::from_be_bytes(*block)
        });
        if !inside {
            return Err(Error::InvalidValue("ipv4 range outside the private blocks"));
        }
        Ok(Self { address, prefix_len })
    }

    /// The network address.
    #[must_use]
    pub fn address(&self) -> [u8; 4] {
        self.address
    }

    /// The prefix length.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// How many addresses the range spans, network and broadcast included.
    #[must_use]
    pub fn size(&self) -> u64 {
        1_u64.checked_shl(32_u32.saturating_sub(u32::from(self.prefix_len))).unwrap_or(0)
    }

    /// Whether `address` lies inside the range.
    #[must_use]
    pub fn contains(&self, address: [u8; 4]) -> bool {
        u32::from_be_bytes(address) & mask(self.prefix_len) == u32::from_be_bytes(self.address)
    }

    /// The five encoded bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; IPV4_RANGE_LEN] {
        let [a, b, c, d] = self.address;
        [a, b, c, d, self.prefix_len]
    }

    /// Reads the encoded value of the `ipv4` key.
    ///
    /// # Errors
    ///
    /// An empty value is refused as a second spelling of absence; any other
    /// wrong length, and any range [`Self::new`] refuses, likewise.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        match bytes {
            [] => Err(Error::InvalidValue("empty ipv4 range")),
            [a, b, c, d, prefix_len] => Self::new([*a, *b, *c, *d], *prefix_len),
            _ => Err(Error::InvalidValue("ipv4 range length")),
        }
    }
}

/// The netmask of a prefix length, zero for zero.
fn mask(prefix_len: u8) -> u32 {
    u32::MAX.checked_shl(32_u32.saturating_sub(u32::from(prefix_len))).unwrap_or(0)
}

impl core::fmt::Display for Ipv4Range {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let [a, b, c, d] = self.address;
        write!(f, "{a}.{b}.{c}.{d}/{}", self.prefix_len)
    }
}

impl core::str::FromStr for Ipv4Range {
    type Err = Error;

    /// Reads `a.b.c.d/len`.
    fn from_str(text: &str) -> Result<Self> {
        let (address, prefix_len) =
            text.split_once('/').ok_or(Error::InvalidValue("ipv4 range syntax"))?;
        let address: std::net::Ipv4Addr =
            address.parse().map_err(|_| Error::InvalidValue("ipv4 range syntax"))?;
        let prefix_len: u8 =
            prefix_len.parse().map_err(|_| Error::InvalidValue("ipv4 range syntax"))?;
        Self::new(address.octets(), prefix_len)
    }
}

// ---------------------------------------------------------------------------
// Network parameters
// ---------------------------------------------------------------------------

/// A relay a network is moving away from, and until when it is still used.
///
/// Carried beside the relay rather than instead of it, because a move is a
/// transition and not a switch: nodes learn of a change by synchronising, they
/// synchronise through the relay, and a node switched off when the relay moved
/// wakes knowing only this one. Until [`Self::until`] the nodes that already
/// moved stay reachable here too, so that node finds somebody to learn from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaving {
    /// The relay being left.
    pub relay: String,
    /// Its certificate, if the network pinned one.
    pub relay_cert: Option<Vec<u8>>,
    /// When the transition ends, in milliseconds since the epoch — the same
    /// clock operations are dated by.
    pub until: u64,
}

/// Network-wide parameters carried in the roster.
///
/// The name suffix lives here rather than in the code because a suffix
/// compiled into clients could not be changed without invalidating every
/// certificate and every installed client at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkParams {
    /// The IPv6 ULA prefix bytes.
    pub ula: Vec<u8>,
    /// The IPv4 range devices derive their IPv4 addresses in, if the network
    /// chose one.
    ///
    /// Here rather than in local configuration because every device has to
    /// compute the same address for the same device, or a packet's source stops
    /// matching what its receiver expects.
    ///
    /// `None` is a network that uses [`Ipv4Range::DEFAULT`] — including every
    /// network founded before this field existed, whose parameters therefore
    /// encode exactly as they did. Read it through [`Self::ipv4_range`].
    pub ipv4: Option<Ipv4Range>,
    /// The address of the relay this network uses, if it has one.
    ///
    /// A relay is infrastructure the network depends on for reachability. Left
    /// to each node's local configuration, no two nodes would necessarily agree,
    /// and anyone able to write a node's configuration could point it at a relay
    /// of their choosing — which reveals who talks to whom and when, and can
    /// withhold service, even though it can read nothing. Carrying it here makes
    /// the answer network-wide, signed, and changeable only by the people
    /// allowed to change everything else, through `set_network`.
    ///
    /// `None` is a network with no relay: one confined to a LAN, or one still
    /// being set up. It is not the same as an empty address, which is refused.
    pub relay: Option<String>,
    /// The relay's certificate, if the network pins one. DER.
    ///
    /// Present so the **roster** authenticates the relay. The address above says
    /// where to go; this says who must be there. Without it a node reaching that
    /// address trusts whatever certificate authority happens to vouch for
    /// whoever answers — and a relay learns who talks to whom and when, which is
    /// the one thing §2.8 is careful about even though the relay can read
    /// nothing.
    ///
    /// Pinning here rather than leaning on the certificate authorities is the
    /// same argument the product rests on: the trust root belongs to the network,
    /// on its own devices, not to a third party. It also makes a self-signed
    /// relay a first-class arrangement rather than a workaround — which matters
    /// to anyone running one on an address with no domain name.
    ///
    /// `None` is a network whose relay presents an ordinary publicly trusted
    /// certificate, or one with no relay at all.
    pub relay_cert: Option<Vec<u8>>,
    /// The rendezvous service this network uses, if it has one.
    ///
    /// Where a device publishes the addresses it believes it can be reached at,
    /// and where it looks for a peer's. §2.9 makes it the third path tried,
    /// after the local network and the cached addresses.
    ///
    /// Here for the reason the relay is here. Whoever answers this address
    /// learns which devices are looking for which others and when — less than
    /// the relay learns, and still more than a third party should. Left to local
    /// configuration, no two nodes would necessarily agree and anyone able to
    /// write that file could substitute their own. Signed, it is one answer,
    /// changed by `set_network` like anything else.
    ///
    /// The records it stores are signed and sequence-numbered by the devices
    /// themselves, so a hostile rendezvous can withhold and delay but cannot
    /// forge an address or roll one back. That is why an address is enough here
    /// and no certificate is pinned beside it, unlike the relay.
    ///
    /// `None` is a network with no rendezvous: one confined to a LAN, or one
    /// relying on the relay's own path discovery.
    pub rendezvous: Option<String>,
    /// The DNS suffix, under `.internal`.
    pub suffix: String,
    /// The relay this network is moving away from, while it is.
    ///
    /// `None` is a network that is not moving, which is every network until a
    /// relay is changed. It is left out of the encoding then, so those
    /// parameters encode exactly as they did before this field existed.
    pub leaving: Option<Leaving>,
    /// Snapshot validity window, in seconds.
    pub snapshot_window: u64,
}

impl NetworkParams {
    /// Builds parameters with no relay, checking every bound.
    pub fn new(ula: Vec<u8>, suffix: impl Into<String>, snapshot_window: u64) -> Result<Self> {
        Self::with_relay(ula, None::<String>, suffix, snapshot_window)
    }

    /// Builds parameters, checking every bound.
    ///
    /// An empty relay address is refused rather than treated as absence: absence
    /// already has an encoding, and a second spelling of the same thing would
    /// mean two byte strings decoding to one value.
    pub fn with_relay(
        ula: Vec<u8>,
        relay: Option<impl Into<String>>,
        suffix: impl Into<String>,
        snapshot_window: u64,
    ) -> Result<Self> {
        let suffix = suffix.into();
        let relay = relay.map(Into::into);
        if ula.len() > limits::MAX_ULA_PREFIX_LEN {
            return Err(Error::LimitExceeded("ula prefix length"));
        }
        // Both become configuration of every member's operating system: the
        // suffix a resolution rule, the prefix a route. Checked here, where
        // building and decoding meet, so parameters that would claim a public
        // name or route public space never become a network's parameters on any
        // node. See `crate::params`.
        crate::params::unique_local_prefix(&ula)?;
        crate::params::private_suffix(&suffix)?;
        match &relay {
            Some(address) if address.len() > limits::MAX_RELAY_LEN => {
                return Err(Error::LimitExceeded("relay address length"));
            }
            Some(address) if address.is_empty() => {
                return Err(Error::InvalidValue("empty relay address"));
            }
            _ => {}
        }
        Ok(Self {
            ula,
            ipv4: None,
            relay,
            relay_cert: None,
            rendezvous: None,
            suffix,
            leaving: None,
            snapshot_window,
        })
    }

    /// Chooses the IPv4 range. The range was checked when it was built.
    #[must_use]
    pub fn in_ipv4_range(mut self, range: Ipv4Range) -> Self {
        self.ipv4 = Some(range);
        self
    }

    /// The IPv4 range in force: the chosen one, or the default.
    #[must_use]
    pub fn ipv4_range(&self) -> Ipv4Range {
        self.ipv4.unwrap_or(Ipv4Range::DEFAULT)
    }

    /// Pins the relay's certificate.
    ///
    /// # Errors
    ///
    /// When the certificate is empty or longer than the bound. Empty is refused
    /// rather than treated as absence: absence already has an encoding, and a
    /// second spelling of the same thing would mean two byte strings decoding to
    /// one value.
    pub fn pinning(mut self, certificate: Vec<u8>) -> Result<Self> {
        if certificate.is_empty() {
            return Err(Error::InvalidValue("empty relay certificate"));
        }
        if certificate.len() > limits::MAX_RELAY_CERT_LEN {
            return Err(Error::LimitExceeded("relay certificate length"));
        }
        self.relay_cert = Some(certificate);
        Ok(self)
    }

    /// The parameters for moving this network to `relay`, issued at `issued`
    /// (milliseconds since the epoch).
    ///
    /// Everything else is carried over unchanged: a relay change that could also
    /// move the suffix or the IPv4 range would put them one typo away.
    ///
    /// The current relay becomes the one being left, for one freshness window —
    /// the `snapshot_window` of the parameters being replaced, which is a limit
    /// the network already has. A move during a move leaves the current relay and
    /// drops the older one: two relays being left would be a network with no
    /// settled answer to where it can be reached. A network with no relay yet is
    /// given one, with nothing to leave.
    ///
    /// # Errors
    ///
    /// As [`Self::leaving`], and when the new relay or certificate is outside its
    /// bound.
    pub fn moving_to(
        &self,
        relay: impl Into<String>,
        relay_cert: Option<Vec<u8>>,
        issued: u64,
    ) -> Result<Self> {
        let relay = relay.into();
        let window_ms = self.snapshot_window.saturating_mul(1_000);
        let leaving = self.relay.clone().map(|current| Leaving {
            relay: current,
            relay_cert: self.relay_cert.clone(),
            until: issued.saturating_add(window_ms),
        });

        let mut moved =
            Self::with_relay(self.ula.clone(), Some(relay), &*self.suffix, self.snapshot_window)?;
        moved.ipv4 = self.ipv4;
        moved.rendezvous = self.rendezvous.clone();
        let moved = match relay_cert {
            Some(certificate) => moved.pinning(certificate)?,
            None => moved,
        };
        match leaving {
            Some(leaving) => moved.leaving(leaving),
            None => Ok(moved),
        }
    }

    /// The parameters for moving this network to `relay` **at once**, with no
    /// transition.
    ///
    /// For a relay that is gone or must not be used another hour. Every node
    /// moves as soon as it holds the change, and a device switched off at that
    /// moment has no relay on which to learn of it — which is why this is its own
    /// function rather than a flag on [`Self::moving_to`], and why whoever calls
    /// it is expected to have said so to a person first.
    ///
    /// # Errors
    ///
    /// When the new relay or certificate is outside its bound.
    pub fn switching_to(
        &self,
        relay: impl Into<String>,
        relay_cert: Option<Vec<u8>>,
    ) -> Result<Self> {
        let mut moved = Self::with_relay(
            self.ula.clone(),
            Some(relay.into()),
            &*self.suffix,
            self.snapshot_window,
        )?;
        moved.ipv4 = self.ipv4;
        moved.rendezvous = self.rendezvous.clone();
        match relay_cert {
            Some(certificate) => moved.pinning(certificate),
            None => Ok(moved),
        }
    }

    /// The relay being left, while the transition has not ended at `now`
    /// (milliseconds since the epoch).
    ///
    /// **The end is the rule, not the next change.** Past it, the relay being
    /// left is no longer in use even though the parameters still name it —
    /// nothing has to be signed for a transition to finish.
    #[must_use]
    pub fn leaving_at(&self, now: u64) -> Option<&Leaving> {
        self.leaving.as_ref().filter(|leaving| now < leaving.until)
    }

    /// Records that this network is leaving `leaving`, until its end.
    ///
    /// # Errors
    ///
    /// When there is no relay to move *to* — a network leaving a relay for none
    /// would be one reachable on nothing once the transition ended — when the
    /// relay being left is the relay, or when it or its certificate is outside
    /// its bound. The relay is compared as written: two spellings of one relay
    /// are refused before anything is signed, where the network's own relays
    /// can be compared the way admission compares them.
    pub fn leaving(mut self, leaving: Leaving) -> Result<Self> {
        let Some(relay) = self.relay.as_deref() else {
            return Err(Error::InvalidValue("a relay being left with no relay to move to"));
        };
        if leaving.relay == relay {
            return Err(Error::InvalidValue("the relay being left is the relay"));
        }
        if leaving.relay.is_empty() {
            return Err(Error::InvalidValue("empty relay address"));
        }
        if leaving.relay.len() > limits::MAX_RELAY_LEN {
            return Err(Error::LimitExceeded("relay address length"));
        }
        match &leaving.relay_cert {
            Some(certificate) if certificate.is_empty() => {
                return Err(Error::InvalidValue("empty relay certificate"));
            }
            Some(certificate) if certificate.len() > limits::MAX_RELAY_CERT_LEN => {
                return Err(Error::LimitExceeded("relay certificate length"));
            }
            _ => {}
        }
        self.leaving = Some(leaving);
        Ok(self)
    }

    /// Names the rendezvous service.
    ///
    /// # Errors
    ///
    /// When the address is empty or longer than the bound. Empty is refused for
    /// the reason an empty relay address is: absence already has an encoding.
    pub fn meeting_at(mut self, address: impl Into<String>) -> Result<Self> {
        let address = address.into();
        if address.is_empty() {
            return Err(Error::InvalidValue("empty rendezvous address"));
        }
        if address.len() > limits::MAX_RENDEZVOUS_LEN {
            return Err(Error::LimitExceeded("rendezvous address length"));
        }
        self.rendezvous = Some(address);
        Ok(self)
    }

    /// Writes the parameters.
    ///
    /// The relay, its certificate and the rendezvous are each an array of
    /// nothing or of one value, so absence has exactly one encoding. The IPv4
    /// range is instead left out when absent, so that parameters without one
    /// encode exactly as they did before it existed.
    pub(crate) fn encode(&self, writer: &mut Writer) {
        let present = 6_u64
            .saturating_add(u64::from(self.ipv4.is_some()))
            .saturating_add(u64::from(self.leaving.is_some()));
        writer.map(present);
        writer.key("ula").bytes(&self.ula);
        if let Some(range) = &self.ipv4 {
            writer.key("ipv4").bytes(&range.to_bytes());
        }
        writer.key("relay");
        match &self.relay {
            Some(address) => {
                writer.array(1);
                writer.str(address);
            }
            None => {
                writer.array(0);
            }
        }
        writer.key("suffix").str(&self.suffix);
        if let Some(leaving) = &self.leaving {
            writer.key("leaving").map(3);
            writer.key("relay").str(&leaving.relay);
            writer.key("until").u64(leaving.until);
            writer.key("relay_cert");
            match &leaving.relay_cert {
                Some(certificate) => {
                    writer.array(1);
                    writer.bytes(certificate);
                }
                None => {
                    writer.array(0);
                }
            }
        }
        writer.key("relay_cert");
        match &self.relay_cert {
            Some(certificate) => {
                writer.array(1);
                writer.bytes(certificate);
            }
            None => {
                writer.array(0);
            }
        }
        writer.key("rendezvous");
        match &self.rendezvous {
            Some(address) => {
                writer.array(1);
                writer.str(address);
            }
            None => {
                writer.array(0);
            }
        }
        writer.key("snapshot_window").u64(self.snapshot_window);
    }

    /// Reads the parameters.
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let mut map = reader.map_with_optional(NETWORK_PARAMS_SCHEMA, NETWORK_PARAMS_OPTIONAL)?;
        let ula = map.key("ula")?.bytes(limits::MAX_ULA_PREFIX_LEN, "ula prefix length")?.to_vec();
        let ipv4 = match map.optional_key("ipv4")? {
            // The bound is one over the encoded length, so that a value one byte
            // too long is refused as a wrong length rather than as a limit.
            Some(value) => Some(Ipv4Range::from_bytes(
                value.bytes(IPV4_RANGE_LEN.saturating_add(1), "ipv4 range length")?,
            )?),
            None => None,
        };
        let relay = {
            let value = map.key("relay")?;
            // At most one: an array of two addresses would be a network with two
            // answers to the same question.
            match value.array(1, "relay")? {
                0 => None,
                _ => Some(value.str(limits::MAX_RELAY_LEN, "relay address length")?.to_owned()),
            }
        };
        let suffix = map.key("suffix")?.str(limits::MAX_SUFFIX_LEN, "suffix length")?.to_owned();
        // One key holding all three, so a relay being left without an end, or an
        // end without a relay, is not something the encoding can say at all.
        let leaving = match map.optional_key("leaving")? {
            Some(value) => {
                let mut group = value.map(LEAVING_SCHEMA)?;
                let relay = group
                    .key("relay")?
                    .str(limits::MAX_RELAY_LEN, "relay address length")?
                    .to_owned();
                let until = group.key("until")?.u64()?;
                let relay_cert = {
                    let certificate = group.key("relay_cert")?;
                    match certificate.array(1, "relay_cert")? {
                        0 => None,
                        _ => Some(
                            certificate
                                .bytes(limits::MAX_RELAY_CERT_LEN, "relay certificate length")?
                                .to_vec(),
                        ),
                    }
                };
                group.finish()?;
                Some(Leaving { relay, relay_cert, until })
            }
            None => None,
        };
        let relay_cert = {
            let value = map.key("relay_cert")?;
            match value.array(1, "relay_cert")? {
                0 => None,
                _ => Some(
                    value.bytes(limits::MAX_RELAY_CERT_LEN, "relay certificate length")?.to_vec(),
                ),
            }
        };
        let rendezvous = {
            let value = map.key("rendezvous")?;
            match value.array(1, "rendezvous")? {
                0 => None,
                _ => Some(
                    value.str(limits::MAX_RENDEZVOUS_LEN, "rendezvous address length")?.to_owned(),
                ),
            }
        };
        let snapshot_window = map.key("snapshot_window")?.u64()?;
        map.finish()?;

        let params = Self::with_relay(ula, relay, suffix, snapshot_window)?;
        let params = match ipv4 {
            Some(range) => params.in_ipv4_range(range),
            None => params,
        };
        let params = match relay_cert {
            Some(certificate) => params.pinning(certificate)?,
            None => params,
        };
        let params = match rendezvous {
            Some(address) => params.meeting_at(address)?,
            None => params,
        };
        match leaving {
            Some(leaving) => params.leaving(leaving),
            None => Ok(params),
        }
    }
}

// ---------------------------------------------------------------------------
// Operation bodies
// ---------------------------------------------------------------------------

/// The payload of an operation, one variant per type.
///
/// Each variant has its own field schema, so a body belonging to one type
/// cannot be read where another type's body is expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationBody {
    /// Establishes the network with its founding admin, who is a founder.
    CreateNetwork {
        /// The founding admin device.
        device: DeviceSpec,
        /// Initial network parameters.
        params: NetworkParams,
    },
    /// Adds a device.
    AddDevice(DeviceSpec),
    /// Revokes a device, definitively.
    RevokeDevice {
        /// The device losing its place.
        device: DeviceId,
        /// Why, for the person who has to decide what to do next.
        reason: String,
    },
    /// Raises a device to admin, optionally granting founder status.
    Promote {
        /// The device being promoted.
        device: DeviceId,
        /// Whether the promotion also grants founder status.
        founder: bool,
    },
    /// Lowers a device to member.
    Demote {
        /// The device being demoted.
        device: DeviceId,
    },
    /// Changes a device's name.
    Rename {
        /// The device being renamed.
        device: DeviceId,
        /// Its new name.
        name: String,
    },
    /// Replaces the network parameters.
    SetNetwork(NetworkParams),
}

impl OperationBody {
    /// The operation type this body belongs to.
    #[must_use]
    pub const fn operation_type(&self) -> OperationType {
        match self {
            Self::CreateNetwork { .. } => OperationType::CreateNetwork,
            Self::AddDevice(_) => OperationType::AddDevice,
            Self::RevokeDevice { .. } => OperationType::RevokeDevice,
            Self::Promote { .. } => OperationType::Promote,
            Self::Demote { .. } => OperationType::Demote,
            Self::Rename { .. } => OperationType::Rename,
            Self::SetNetwork(_) => OperationType::SetNetwork,
        }
    }

    /// The body's canonical bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.write(&mut writer);
        writer.finish()
    }

    /// Writes the body.
    fn write(&self, writer: &mut Writer) {
        match self {
            Self::CreateNetwork { device, params } => {
                writer.map(2);
                writer.key("device");
                device.encode(writer);
                writer.key("params");
                params.encode(writer);
            }
            Self::AddDevice(device) => device.encode(writer),
            Self::RevokeDevice { device, reason } => {
                writer.map(2);
                writer.key("device");
                device.encode(writer);
                writer.key("reason").str(reason);
            }
            Self::Promote { device, founder } => {
                writer.map(2);
                writer.key("device");
                device.encode(writer);
                writer.key("founder").bool(*founder);
            }
            Self::Demote { device } => {
                writer.map(1);
                writer.key("device");
                device.encode(writer);
            }
            Self::Rename { device, name } => {
                writer.map(2);
                writer.key("name").str(name);
                writer.key("device");
                device.encode(writer);
            }
            Self::SetNetwork(params) => params.encode(writer),
        }
    }

    /// Reads a body of the declared type from its own byte string.
    ///
    /// If the bytes fail under the declared type but succeed under a different
    /// one, the complaint is that the body belongs to another operation —
    /// which is more useful than whatever structural error the mismatch
    /// happened to produce first.
    pub(crate) fn decode(body_bytes: &[u8], declared: OperationType) -> Result<Self> {
        match Self::decode_as(body_bytes, declared) {
            Ok(body) => Ok(body),
            Err(original) => {
                let fits_another_type = OperationType::ALL
                    .iter()
                    .filter(|candidate| **candidate != declared)
                    .any(|candidate| Self::decode_as(body_bytes, *candidate).is_ok());
                if fits_another_type { Err(Error::BodySchema) } else { Err(original) }
            }
        }
    }

    /// Reads a body strictly as the given type.
    fn decode_as(body_bytes: &[u8], as_type: OperationType) -> Result<Self> {
        let mut reader = Reader::new(body_bytes);
        let body = match as_type {
            OperationType::CreateNetwork => {
                let mut map = reader.map(CREATE_NETWORK_SCHEMA)?;
                let device = DeviceSpec::decode(map.key("device")?)?;
                let params = NetworkParams::decode(map.key("params")?)?;
                map.finish()?;
                Self::CreateNetwork { device, params }
            }
            OperationType::AddDevice => Self::AddDevice(DeviceSpec::decode(&mut reader)?),
            OperationType::RevokeDevice => {
                let mut map = reader.map(REVOKE_DEVICE_SCHEMA)?;
                let device = DeviceId::decode(map.key("device")?)?;
                let reason =
                    map.key("reason")?.str(limits::MAX_REASON_LEN, "reason length")?.to_owned();
                map.finish()?;
                Self::RevokeDevice { device, reason }
            }
            OperationType::Promote => {
                let mut map = reader.map(PROMOTE_SCHEMA)?;
                let device = DeviceId::decode(map.key("device")?)?;
                let founder = map.key("founder")?.bool()?;
                map.finish()?;
                Self::Promote { device, founder }
            }
            OperationType::Demote => {
                let mut map = reader.map(DEMOTE_SCHEMA)?;
                let device = DeviceId::decode(map.key("device")?)?;
                map.finish()?;
                Self::Demote { device }
            }
            OperationType::Rename => {
                let mut map = reader.map(RENAME_SCHEMA)?;
                let name =
                    map.key("name")?.str(limits::MAX_NAME_LEN, "device name length")?.to_owned();
                let device = DeviceId::decode(map.key("device")?)?;
                map.finish()?;
                Self::Rename { device, name }
            }
            OperationType::SetNetwork => Self::SetNetwork(NetworkParams::decode(&mut reader)?),
        };
        reader.finish()?;
        Ok(body)
    }
}

// ---------------------------------------------------------------------------
// The signed core
// ---------------------------------------------------------------------------

/// The part of an operation that is signed and hashed.
///
/// Excludes `id` and `sig`. Everything else is inside, including `alg`, so an
/// algorithm cannot be swapped after signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationCore {
    /// Wall-clock milliseconds since the Unix epoch, for display only.
    ///
    /// Nothing reads this to decide ordering, validity, or identity. Causal
    /// order comes from `parents`; a clock that is wrong, or a peer whose
    /// clock is a lie, changes nothing about how the roster merges.
    pub ts: u64,
    /// The algorithm of the signature over this core.
    pub alg: Algorithm,
    /// The payload.
    pub body: OperationBody,
    /// Ids of the operations the author knew when authoring this one.
    pub parents: Vec<OperationId>,
    /// The id of the key that signed this operation.
    pub author: KeyId,
    /// The network this operation belongs to.
    pub network: NetworkId,
}

impl OperationCore {
    /// Builds a core, checking the parent count.
    pub fn new(
        ts: u64,
        alg: Algorithm,
        body: OperationBody,
        parents: Vec<OperationId>,
        author: KeyId,
        network: NetworkId,
    ) -> Result<Self> {
        if parents.len() > limits::MAX_PARENTS {
            return Err(Error::LimitExceeded("parent count"));
        }
        Ok(Self { ts, alg, body, parents, author, network })
    }

    /// This core's operation type.
    #[must_use]
    pub const fn operation_type(&self) -> OperationType {
        self.body.operation_type()
    }

    /// The canonical bytes of this core: what is signed, and what is hashed.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.map(7);
        writer.key("ts").u64(self.ts);
        writer.key("alg").str(self.alg.as_str());
        writer.key("body").bytes(&self.body.encode());
        writer.key("type").str(self.operation_type().as_str());
        writer.key("author");
        self.author.encode(&mut writer);
        writer.key("network");
        self.network.encode(&mut writer);
        writer.key("parents").array(self.parents.len() as u64);
        for parent in &self.parents {
            parent.encode(&mut writer);
        }
        writer.finish()
    }

    /// This operation's id.
    #[must_use]
    pub fn id(&self) -> OperationId {
        OperationId::of_core(&self.encode())
    }

    /// Reads a core from its canonical bytes.
    ///
    /// Public because an operation that has been prepared and not yet signed is
    /// a thing somebody has to be **shown** before they authorise it — and what
    /// they are shown must be read from the bytes that will be signed rather
    /// than from a description sent beside them. A component that supplies both
    /// the bytes and their label can label them as anything.
    ///
    /// # Errors
    ///
    /// When the bytes are not a canonical operation core.
    pub fn decode(core_bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(core_bytes);
        let mut map = reader.map(CORE_SCHEMA)?;
        let ts = map.key("ts")?.u64()?;
        let alg = Algorithm::parse(map.key("alg")?.str(limits::MAX_MAP_KEY_LEN, "alg")?)?;
        // Held as raw bytes: canonical order puts `body` before `type`, so the
        // schema governing these bytes is not yet known.
        let body_bytes = map.key("body")?.bytes(limits::MAX_OPERATION_SIZE, "body size")?;
        let declared =
            OperationType::parse(map.key("type")?.str(limits::MAX_MAP_KEY_LEN, "type")?)?;
        let author = KeyId::decode(map.key("author")?)?;
        let network = NetworkId::decode(map.key("network")?)?;
        let parents = decode_parents(map.key("parents")?)?;
        map.finish()?;
        reader.finish()?;

        let body = OperationBody::decode(body_bytes, declared)?;
        Self::new(ts, alg, body, parents, author, network)
    }
}

/// Reads the parent id list.
fn decode_parents(reader: &mut Reader<'_>) -> Result<Vec<OperationId>> {
    let count = reader.array(limits::MAX_PARENTS, "parent count")?;
    let mut parents = Vec::with_capacity(count);
    for _ in 0..count {
        parents.push(OperationId::decode(reader)?);
    }
    Ok(parents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;

    /// Every schema is written by hand. If one drifts out of canonical order,
    /// the encoder and the decoder still agree with each other but disagree
    /// with every other implementation — the worst kind of bug this format
    /// can have.
    #[test]
    fn every_schema_is_in_canonical_order() {
        for schema in ALL_SCHEMAS {
            assert!(
                cbor::is_canonical_schema(schema),
                "schema {schema:?} is not in canonical key order"
            );
        }
    }

    // ---- a network moving relay ------------------------------------------

    fn on(relay: &str) -> NetworkParams {
        NetworkParams::with_relay(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            Some(relay),
            "casa.internal",
            604_800,
        )
        .expect("well-formed")
    }

    fn round_trip(params: &NetworkParams) -> Result<NetworkParams> {
        let mut writer = cbor::Writer::new();
        params.encode(&mut writer);
        let bytes = writer.finish();
        let mut reader = cbor::Reader::new(&bytes);
        let back = NetworkParams::decode(&mut reader)?;
        reader.finish()?;
        Ok(back)
    }

    /// A move carries the relay it leaves, and changes nothing else.
    #[test]
    fn a_move_carries_the_relay_it_leaves_and_nothing_else() {
        let before = on("https://a.example:443")
            .pinning(vec![0xaa; 4])
            .expect("pins")
            .in_ipv4_range("10.42.0.0/16".parse().expect("allowed"))
            .meeting_at("https://meet.example")
            .expect("names it");

        let issued = 1_735_689_600_000;
        let after =
            before.moving_to("https://b.example:443", Some(vec![0xbb; 4]), issued).expect("moves");

        assert_eq!(Some("https://b.example:443"), after.relay.as_deref());
        assert_eq!(Some(vec![0xbb; 4]), after.relay_cert);
        let leaving = after.leaving.clone().expect("it is leaving something");
        assert_eq!("https://a.example:443", leaving.relay);
        assert_eq!(Some(vec![0xaa; 4]), leaving.relay_cert, "with the certificate it had");
        assert_eq!(issued + 604_800 * 1_000, leaving.until, "one freshness window after");

        // Everything else, untouched.
        assert_eq!(before.ula, after.ula);
        assert_eq!(before.ipv4, after.ipv4);
        assert_eq!(before.suffix, after.suffix);
        assert_eq!(before.rendezvous, after.rendezvous);
        assert_eq!(before.snapshot_window, after.snapshot_window);

        assert_eq!(Ok(after.clone()), round_trip(&after), "and it survives its own encoding");
    }

    /// A move during a move leaves one relay behind, not two.
    #[test]
    fn a_move_during_a_move_drops_the_older_relay() {
        let issued = 1_735_689_600_000;
        let to_b = on("https://a.example:443")
            .moving_to("https://b.example:443", None, issued)
            .expect("moves");
        let to_c = to_b.moving_to("https://c.example:443", None, issued + 1).expect("moves again");

        assert_eq!(Some("https://c.example:443"), to_c.relay.as_deref());
        let leaving = to_c.leaving.expect("leaving the one it was on");
        assert_eq!("https://b.example:443", leaving.relay);
        let encoded = {
            let mut writer = cbor::Writer::new();
            to_c_encoded(&mut writer);
            writer.finish()
        };
        assert!(
            !encoded.windows(b"a.example".len()).any(|w| w == b"a.example"),
            "the first relay appears nowhere"
        );

        fn to_c_encoded(writer: &mut cbor::Writer) {
            let issued = 1_735_689_600_000;
            on("https://a.example:443")
                .moving_to("https://b.example:443", None, issued)
                .and_then(|to_b| to_b.moving_to("https://c.example:443", None, issued + 1))
                .expect("moves")
                .encode(writer);
        }
    }

    /// A network with no relay is given one, with nothing to leave.
    #[test]
    fn a_first_relay_is_not_a_move() {
        let none = NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "casa.internal", 604_800)
            .expect("well-formed");
        let given = none.moving_to("https://a.example:443", None, 1).expect("given one");
        assert_eq!(Some("https://a.example:443"), given.relay.as_deref());
        assert!(given.leaving.is_none(), "there was nothing to leave");
    }

    /// An immediate move leaves nothing behind, even mid-transition.
    #[test]
    fn an_immediate_move_leaves_nothing_to_find() {
        let moving =
            on("https://a.example:443").moving_to("https://b.example:443", None, 1).expect("moves");
        let now = moving.switching_to("https://c.example:443", None).expect("switches");
        assert_eq!(Some("https://c.example:443"), now.relay.as_deref());
        assert!(now.leaving.is_none(), "no relay being left, not even the one in flight");
        assert_eq!(moving.suffix, now.suffix);
    }

    /// The group is refused where it cannot mean anything.
    #[test]
    fn a_relay_being_left_is_refused_where_it_means_nothing() {
        let leaving =
            |relay: &str| Leaving { relay: relay.to_owned(), relay_cert: None, until: 10 };

        let same = on("https://a.example:443").leaving(leaving("https://a.example:443"));
        assert_eq!(Err(Error::InvalidValue("the relay being left is the relay")), same);

        let nowhere = NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "casa.internal", 604_800)
            .expect("well-formed")
            .leaving(leaving("https://a.example:443"));
        assert_eq!(
            Err(Error::InvalidValue("a relay being left with no relay to move to")),
            nowhere
        );

        let empty = on("https://b.example:443").leaving(leaving(""));
        assert_eq!(Err(Error::InvalidValue("empty relay address")), empty);
    }

    /// **All or nothing, by construction.** A `leaving` group missing its end is
    /// not a group the encoding can carry: it is refused as a missing field,
    /// before anything is judged.
    #[test]
    fn a_partial_group_does_not_decode() {
        let mut writer = cbor::Writer::new();
        writer.map(7);
        writer.key("ula").bytes(&[0xfd, 0, 0, 0, 0, 0, 0, 0]);
        writer.key("relay").array(1).str("https://b.example:443");
        writer.key("suffix").str("casa.internal");
        writer.key("leaving").map(2);
        writer.key("relay").str("https://a.example:443");
        writer.key("relay_cert").array(0);
        writer.key("relay_cert").array(0);
        writer.key("rendezvous").array(0);
        writer.key("snapshot_window").u64(604_800);
        let bytes = writer.finish();

        let decoded = NetworkParams::decode(&mut cbor::Reader::new(&bytes));
        assert_eq!(Err(Error::MissingField), decoded, "an end is not optional inside the group");
    }

    /// The end is the rule: past it, the relay being left is not in use, with
    /// nothing signed to say so.
    #[test]
    fn a_transition_ends_on_its_own() {
        let issued = 1_000;
        let moving = on("https://a.example:443")
            .moving_to("https://b.example:443", None, issued)
            .expect("moves");
        let end = issued + 604_800 * 1_000;

        assert!(moving.leaving_at(end - 1).is_some(), "still in use a moment before");
        assert!(moving.leaving_at(end).is_none(), "and not at the end");
    }

    /// The core's key order is the format's own demonstration that canonical
    /// order is length-first: `ts` precedes `alg` even though `alg` precedes
    /// `ts` alphabetically.
    #[test]
    fn core_schema_disagrees_with_alphabetical_order() {
        let mut alphabetical = CORE_SCHEMA.to_vec();
        alphabetical.sort_unstable();
        assert_ne!(
            alphabetical.as_slice(),
            CORE_SCHEMA,
            "if these agreed the corpus would not catch an alphabetically-ordered encoder"
        );
        assert_eq!(CORE_SCHEMA.first(), Some(&"ts"));
        assert_eq!(alphabetical.first(), Some(&"alg"));
    }

    #[test]
    fn device_records_round_trip_and_check_their_own_id() {
        let signing = KeyEntry::new(Algorithm::Ed25519, KeyPurpose::Signing, vec![7u8; 32])
            .expect("well-formed");
        let attestation = KeyEntry::new(Algorithm::Ed25519, KeyPurpose::Attestation, vec![8u8; 32])
            .expect("well-formed");
        let mut keys = vec![signing, attestation];
        keys.sort_by_key(KeyEntry::order_key);
        let spec = DeviceSpec::new(keys, "nas", Role::Member, false, vec![]).expect("well-formed");
        let record =
            spec.into_record(OperationId::from_bytes([1u8; 32])).expect("has a signing key");

        let bytes = record.to_bytes();
        assert_eq!(DeviceRecord::from_bytes(&bytes), Ok(record.clone()));
        assert_eq!(DeviceRecord::from_bytes(&bytes).map(|r| r.to_bytes()), Ok(bytes.clone()));

        // A record whose stated id disagrees with its own signing key is not a
        // record with a stale field; it is a record about a different device.
        let mut wrong = record;
        wrong.id = DeviceId::from_bytes([0xff; 32]);
        assert_eq!(DeviceRecord::from_bytes(&wrong.to_bytes()), Err(Error::IdMismatch));
    }

    #[test]
    fn wire_names_round_trip() {
        for value in [Algorithm::Ed25519, Algorithm::P256] {
            assert_eq!(Algorithm::parse(value.as_str()), Ok(value));
        }
        for value in [KeyPurpose::Signing, KeyPurpose::Transport] {
            assert_eq!(KeyPurpose::parse(value.as_str()), Ok(value));
        }
        for value in [Role::Admin, Role::Member] {
            assert_eq!(Role::parse(value.as_str()), Ok(value));
        }
        for value in OperationType::ALL {
            assert_eq!(OperationType::parse(value.as_str()), Ok(*value));
        }
    }

    #[test]
    fn the_operation_type_set_is_closed() {
        assert_eq!(OperationType::ALL.len(), 7);
        assert_eq!(OperationType::parse("delegate"), Err(Error::UnknownOperationType));
        assert_eq!(OperationType::parse(""), Err(Error::UnknownOperationType));
    }

    #[test]
    fn unknown_algorithm_is_an_error_not_a_skip() {
        assert_eq!(Algorithm::parse("ml-dsa-65"), Err(Error::UnknownAlgorithm));
        assert_eq!(Algorithm::parse("ED25519"), Err(Error::UnknownAlgorithm));
    }

    #[test]
    fn unknown_role_and_purpose_are_rejected() {
        assert_eq!(Role::parse("owner"), Err(Error::InvalidValue("role")));
        assert_eq!(KeyPurpose::parse("encryption"), Err(Error::InvalidValue("purpose")));
    }

    // -----------------------------------------------------------------------
    // The IPv4 range
    // -----------------------------------------------------------------------

    fn text(out: &mut Vec<u8>, value: &str) {
        let mut writer = Writer::new();
        writer.str(value);
        out.extend(writer.finish());
    }

    fn bytes(out: &mut Vec<u8>, value: &[u8]) {
        let mut writer = Writer::new();
        writer.bytes(value);
        out.extend(writer.finish());
    }

    /// The parameters map as it was written before the range existed, by hand,
    /// with room to place an `ipv4` entry after `ula`.
    fn hand_built(entries: u8, ipv4: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![0xa0 | entries];
        text(&mut out, "ula");
        bytes(&mut out, &[0xfd, 0, 0, 0, 0, 0, 0, 0]);
        for value in ipv4 {
            text(&mut out, "ipv4");
            bytes(&mut out, value);
        }
        text(&mut out, "relay");
        out.push(0x80);
        text(&mut out, "suffix");
        text(&mut out, "example.internal");
        text(&mut out, "relay_cert");
        out.push(0x80);
        text(&mut out, "rendezvous");
        out.push(0x80);
        text(&mut out, "snapshot_window");
        out.push(0x01);
        out
    }

    /// The parameters map by hand with a chosen prefix and suffix, so a decoder
    /// can be offered values no encoder here would produce.
    fn hand_built_with(ula: &[u8], suffix: &str) -> Vec<u8> {
        let mut out = vec![0xa6];
        text(&mut out, "ula");
        bytes(&mut out, ula);
        text(&mut out, "relay");
        out.push(0x80);
        text(&mut out, "suffix");
        text(&mut out, suffix);
        text(&mut out, "relay_cert");
        out.push(0x80);
        text(&mut out, "rendezvous");
        out.push(0x80);
        text(&mut out, "snapshot_window");
        out.push(0x01);
        out
    }

    fn plain() -> NetworkParams {
        NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 1)
            .unwrap_or_else(|_| unreachable!("well-formed"))
    }

    fn encoded(params: &NetworkParams) -> Vec<u8> {
        let mut writer = Writer::new();
        params.encode(&mut writer);
        writer.finish()
    }

    fn decoded(input: &[u8]) -> Result<NetworkParams> {
        let mut reader = Reader::new(input);
        let params = NetworkParams::decode(&mut reader)?;
        reader.finish()?;
        Ok(params)
    }

    /// Parameters without a range are the bytes they always were, so no
    /// existing operation id moves.
    #[test]
    fn parameters_without_a_range_encode_as_before() {
        assert_eq!(encoded(&plain()), hand_built(6, &[]));
        assert_eq!(decoded(&hand_built(6, &[])), Ok(plain()));
        assert_eq!(plain().ipv4_range(), Ipv4Range::DEFAULT);
    }

    #[test]
    fn a_range_round_trips() {
        let range = Ipv4Range::new([10, 42, 0, 0], 16).unwrap_or_else(|_| unreachable!());
        let params = plain().in_ipv4_range(range);
        let bytes = encoded(&params);
        assert_eq!(bytes, hand_built(7, &[&[10, 42, 0, 0, 16]]));
        assert_eq!(decoded(&bytes), Ok(params));
        assert_eq!(decoded(&bytes).map(|params| params.ipv4_range()), Ok(range));
    }

    /// Each wrong spelling is refused, and the reasons tell them apart.
    #[test]
    fn a_range_cannot_be_spelled_two_ways() {
        assert_eq!(
            decoded(&hand_built(7, &[&[]])),
            Err(Error::InvalidValue("empty ipv4 range")),
            "an empty value is not absence"
        );
        assert_eq!(
            decoded(&hand_built(7, &[&[10, 42, 0, 1, 16]])),
            Err(Error::InvalidValue("ipv4 range has host bits set"))
        );
        // One more than the schema, from the schema: this was `8`, and stopped
        // being one too many when `leaving` made the schema eight keys long.
        let too_many = u8::try_from(NETWORK_PARAMS_SCHEMA.len() + 1).unwrap_or(u8::MAX);
        assert_eq!(
            decoded(&hand_built(
                too_many,
                &[&[10, 42, 0, 0, 16], &[10, 42, 0, 0, 16], &[10, 42, 0, 0, 16]]
            )),
            Err(Error::UnknownField),
            "a map one entry too long is refused on its count"
        );
        assert_eq!(
            decoded(&hand_built(7, &[&[10, 42, 0, 0, 16], &[10, 42, 0, 0, 16]])),
            Err(Error::DuplicateKey),
            "a repeated key within the count is refused as a repetition"
        );
        assert_eq!(
            decoded(&hand_built(7, &[&[10, 42, 0, 0]])),
            Err(Error::InvalidValue("ipv4 range length"))
        );
        assert_eq!(
            decoded(&hand_built(7, &[&[10, 42, 0, 0, 16, 0]])),
            Err(Error::InvalidValue("ipv4 range length"))
        );
    }

    /// Both bounds are enforced where the parameters are *read*, not only where
    /// they are built: an operation carrying a public name or a prefix in global
    /// space fails to decode, so it never becomes any node's parameters.
    #[test]
    fn a_suffix_outside_the_private_namespace_fails_to_decode() {
        let refused = |ula: &[u8], suffix: &str| match decoded(&hand_built_with(ula, suffix)) {
            Err(Error::InvalidValue(reason) | Error::LimitExceeded(reason)) => reason,
            other => unreachable!("`{suffix}` must be refused, got {other:?}"),
        };
        let ula = &[0xfd, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(refused(ula, "azienda.it"), "suffix not under a private namespace");
        assert_eq!(refused(ula, "com"), "suffix not under a private namespace");
        assert_eq!(refused(ula, "internal"), "suffix is a bare private namespace");
        assert_eq!(refused(ula, "docker.internal"), "suffix is a reserved name");
        assert_eq!(refused(ula, "Casa.internal"), "suffix label malformed");
        assert_eq!(decoded(&hand_built_with(ula, "casa.internal")).map(|p| p.suffix), {
            Ok("casa.internal".to_owned())
        });
    }

    #[test]
    fn a_prefix_that_is_not_a_unique_local_64_fails_to_decode() {
        let refused = |ula: &[u8]| match decoded(&hand_built_with(ula, "casa.internal")) {
            Err(Error::InvalidValue(reason) | Error::LimitExceeded(reason)) => reason,
            other => unreachable!("{ula:?} must be refused, got {other:?}"),
        };

        assert_eq!(refused(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]), "prefix not unique local");
        assert_eq!(refused(&[0xfc, 0, 0, 0, 0, 0, 0, 0]), "prefix not unique local");
        assert_eq!(refused(&[0xfd, 0, 0, 0]), "prefix not a /64");
        assert_eq!(refused(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0]), "prefix not a /64");
    }

    #[test]
    fn a_range_after_the_relay_is_misordered() {
        let mut out = vec![0xa7];
        text(&mut out, "ula");
        bytes(&mut out, &[0xfd, 0, 0, 0]);
        text(&mut out, "relay");
        out.push(0x80);
        text(&mut out, "ipv4");
        bytes(&mut out, &[10, 42, 0, 0, 16]);
        text(&mut out, "suffix");
        text(&mut out, "example.internal");
        text(&mut out, "relay_cert");
        out.push(0x80);
        text(&mut out, "rendezvous");
        out.push(0x80);
        text(&mut out, "snapshot_window");
        out.push(0x01);
        assert_eq!(decoded(&out), Err(Error::KeyOrdering));
    }

    /// Refusals of a range name the rule and the range.
    #[test]
    fn a_range_outside_what_is_allowed_is_refused() {
        let refused = |text: &str| match text.parse::<Ipv4Range>() {
            Err(Error::InvalidValue(reason)) => reason,
            other => unreachable!("{text} must be refused, got {other:?}"),
        };
        assert_eq!(refused("10.42.0.1/16"), "ipv4 range has host bits set");
        assert_eq!(refused("10.0.0.0/7"), "ipv4 range prefix length");
        assert_eq!(refused("10.0.0.0/29"), "ipv4 range prefix length");
        for text in [
            "8.8.8.0/24",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "240.0.0.0/8",
            "0.0.0.0/8",
            "11.0.0.0/8",
        ] {
            assert_eq!(refused(text), "ipv4 range outside the private blocks", "{text}");
        }
        // Wider than `/8` is refused on its length before its place.
        for text in ["224.0.0.0/4", "240.0.0.0/4"] {
            assert!(refused(text).starts_with("ipv4 range"), "{text}");
        }
        assert_eq!(refused("100.0.0.0/9"), "ipv4 range outside the private blocks");
        assert_eq!(refused("172.0.0.0/12"), "ipv4 range outside the private blocks");
        assert_eq!(refused("10.0.0.0"), "ipv4 range syntax");
    }

    #[test]
    fn every_allowed_block_and_the_bounds_are_accepted() {
        for (block, prefix_len) in IPV4_RANGE_BLOCKS {
            let range = Ipv4Range::new(block, prefix_len).unwrap_or_else(|_| unreachable!());
            assert_eq!(range.to_string().parse::<Ipv4Range>(), Ok(range));
        }
        assert!("192.168.1.0/24".parse::<Ipv4Range>().is_ok());
        assert!("192.168.1.240/28".parse::<Ipv4Range>().is_ok());
        assert_eq!(Ipv4Range::DEFAULT.to_string(), "100.64.0.0/10");
        assert_eq!("100.64.0.0/10".parse::<Ipv4Range>(), Ok(Ipv4Range::DEFAULT));
        assert_eq!(Ipv4Range::DEFAULT.size(), 1 << 22);
        assert!(Ipv4Range::DEFAULT.contains([100, 127, 255, 255]));
        assert!(!Ipv4Range::DEFAULT.contains([100, 128, 0, 0]));
    }
}

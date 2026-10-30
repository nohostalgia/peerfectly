//! Proving that a device belongs, against a state root.
//!
//! A state root is the hash of the network, the root of its devices tree and
//! the root of its parameters tree (see
//! [`crate::state::RosterState::root_of`]). A device's membership is shown by
//! its leaf, the proof of that leaf in the devices tree, and the parameters
//! root beside it: together they recompute the state root, and nothing else
//! does. A member holding no roster checks this with a handful of hashes.

use crate::cbor::{Reader, Writer};
use crate::error::{Error, Result};
use crate::id::{DeviceId, NetworkId};
use crate::leaf::DeviceLeaf;
use crate::merkle::{Hash, Proof};
use crate::state::RosterState;

/// Canonical key order of a membership proof.
pub const MEMBERSHIP_PROOF_SCHEMA: &[&str] = &["devices", "parameters"];

/// A proof that a device's leaf belongs to a state root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipProof {
    /// The leaf's proof within the devices tree.
    pub devices: Proof,
    /// The root of the parameters tree, the devices tree's sibling.
    pub parameters: Hash,
}

impl MembershipProof {
    /// The proof of `device`'s leaf in `state`, if it is a member.
    #[must_use]
    pub fn of(state: &RosterState, device: &DeviceId) -> Option<Self> {
        let devices = state.devices_tree().prove(&DeviceLeaf::position(device))?;
        Some(Self { devices, parameters: state.params.tree().root() })
    }

    /// Whether `leaf` belongs to the state `root` of `network`.
    #[must_use]
    pub fn verifies(&self, root: &Hash, network: &NetworkId, leaf: &DeviceLeaf) -> bool {
        let Some(devices_root) =
            self.devices.root_for(&DeviceLeaf::position(&leaf.record.id), &leaf.value_hash())
        else {
            return false;
        };
        RosterState::root_of(network, &devices_root, &self.parameters) == *root
    }

    /// Writes the proof.
    pub(crate) fn encode(&self, writer: &mut Writer) {
        writer.map(2);
        writer.key("devices");
        self.devices.encode(writer);
        writer.key("parameters").bytes(&self.parameters);
    }

    /// Reads a proof.
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let mut map = reader.map(MEMBERSHIP_PROOF_SCHEMA)?;
        let devices = Proof::decode(map.key("devices")?)?;
        let parameters = Hash::try_from(map.key("parameters")?.fixed_bytes(32)?)
            .map_err(|_| Error::IdentifierLength)?;
        map.finish()?;
        Ok(Self { devices, parameters })
    }
}

/// Canonical key order of a member's evidence.
pub const EVIDENCE_SCHEMA: &[&str] = &["leaf", "root", "proof"];

/// What a member shows a peer as a session opens: its leaf, the proof of it,
/// and the signed root the proof is against.
///
/// Enough for a peer holding no roster to tell a member from a stranger: the
/// leaf names the device and its transport key, the proof shows the leaf is in
/// the root, and the root is signed by an admin. Whether that root is one to
/// believe is the peer's to judge, as it judges any root it is given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// The member's leaf.
    pub leaf: DeviceLeaf,
    /// The leaf's proof against the root.
    pub proof: MembershipProof,
    /// The signed root, as its exact bytes.
    pub root: alloc::vec::Vec<u8>,
}

impl Evidence {
    /// Its canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        let mut writer = Writer::new();
        writer.map(3);
        writer.key("leaf");
        self.leaf.encode(&mut writer);
        writer.key("root").bytes(&self.root);
        writer.key("proof");
        self.proof.encode(&mut writer);
        writer.finish()
    }

    /// Reads evidence, refusing anything not in canonical form.
    ///
    /// # Errors
    ///
    /// When the bytes are not canonical evidence, or the root is larger than a
    /// root may be.
    pub fn from_bytes(input: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(input);
        let mut map = reader.map(EVIDENCE_SCHEMA)?;
        let leaf = DeviceLeaf::decode(map.key("leaf")?)?;
        let root = map.key("root")?.bytes(crate::limits::MAX_SNAPSHOT_SIZE, "root")?.to_vec();
        let proof = MembershipProof::decode(map.key("proof")?)?;
        map.finish()?;
        reader.finish()?;
        Ok(Self { leaf, proof, root })
    }

    /// The device this evidence shows to be a member, and the root it is a
    /// member under — provided `transport_key` is that device's.
    ///
    /// Checks that the root reads as one, that the leaf proves against it, and
    /// that the leaf names `transport_key` for the transport purpose. A proof of
    /// another device's leaf shows nothing about the peer presenting it. The
    /// root's signature and standing are not checked here: they are the
    /// caller's, against what it already holds.
    ///
    /// # Errors
    ///
    /// When the root does not decode, the proof does not lead to it, or the
    /// leaf is not the holder's of `transport_key`.
    pub fn shows(
        &self,
        transport_key: &crate::id::KeyId,
    ) -> Result<(DeviceId, crate::snapshot::RawSnapshot)> {
        let root = crate::snapshot::RawSnapshot::decode(&self.root)?;
        let body = root.body();
        if !self.proof.verifies(&body.root, &body.network, &self.leaf) {
            return Err(Error::SignatureInvalid);
        }
        let holds = self.leaf.record.keys.iter().any(|entry| {
            entry.purpose == crate::types::KeyPurpose::Transport && entry.key_id() == *transport_key
        });
        if !holds {
            return Err(Error::InvalidValue("evidence of another device"));
        }
        Ok((self.leaf.record.id, root))
    }
}

/// Canonical key order of compact evidence.
pub const SHOWN_SCHEMA: &[&str] = &["leaf", "proof", "against"];

/// Evidence without the root: a leaf, its proof, and the hash of the root the
/// proof is against.
///
/// For a peer that already knows the network's roots — another member on the
/// same LAN — and has no room for a root: what a local announcement carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    /// The member's leaf.
    pub leaf: DeviceLeaf,
    /// The leaf's proof.
    pub proof: MembershipProof,
    /// The root the proof is against.
    pub against: Hash,
}

impl Shown {
    /// The device this compact evidence is, where its leaf names
    /// `transport_key` for the transport purpose: a proof of another device's
    /// leaf shows nothing about the peer presenting it. Whether the proof
    /// holds, and against a root to believe, is the caller's, against what it
    /// holds: only it knows the network and its roots.
    ///
    /// # Errors
    ///
    /// When the leaf is not the holder's of `transport_key`.
    pub fn shows(&self, transport_key: &crate::id::KeyId) -> Result<DeviceId> {
        let holds = self.leaf.record.keys.iter().any(|entry| {
            entry.purpose == crate::types::KeyPurpose::Transport && entry.key_id() == *transport_key
        });
        if !holds {
            return Err(Error::InvalidValue("evidence of another device"));
        }
        Ok(self.leaf.record.id)
    }

    /// Its canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        let mut writer = Writer::new();
        writer.map(3);
        writer.key("leaf");
        self.leaf.encode(&mut writer);
        writer.key("proof");
        self.proof.encode(&mut writer);
        writer.key("against").bytes(&self.against);
        writer.finish()
    }

    /// Reads compact evidence, refusing anything not canonical.
    ///
    /// # Errors
    ///
    /// When the bytes are not canonical compact evidence.
    pub fn from_bytes(input: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(input);
        let mut map = reader.map(SHOWN_SCHEMA)?;
        let leaf = DeviceLeaf::decode(map.key("leaf")?)?;
        let proof = MembershipProof::decode(map.key("proof")?)?;
        let against = Hash::try_from(map.key("against")?.fixed_bytes(32)?)
            .map_err(|_| Error::IdentifierLength)?;
        map.finish()?;
        reader.finish()?;
        Ok(Self { leaf, proof, against })
    }
}

impl Evidence {
    /// The same evidence, with the root's hash in place of the root.
    ///
    /// # Errors
    ///
    /// When the root does not read.
    pub fn shown(&self) -> Result<Shown> {
        let root = crate::snapshot::RawSnapshot::decode(&self.root)?;
        Ok(Shown { leaf: self.leaf.clone(), proof: self.proof.clone(), against: root.body().root })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::cbor::is_canonical_schema;

    #[test]
    fn the_schema_is_canonical() {
        assert!(is_canonical_schema(MEMBERSHIP_PROOF_SCHEMA));
        assert!(is_canonical_schema(EVIDENCE_SCHEMA));
        assert!(is_canonical_schema(SHOWN_SCHEMA));
    }
}

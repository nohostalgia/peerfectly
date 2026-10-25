//! Moving a whole state from one full member to another, in pieces.
//!
//! A root commits to its state by hash, so the state itself has to travel some
//! other way to a member that holds nothing yet — a full member just admitted,
//! or an anchor started on a fresh disk. It travels as the leaves themselves,
//! cut into pieces that each fit the ordinary message limits, whatever the size
//! of the network.
//!
//! Nothing in a piece is believed until the last one is in: the receiver
//! rebuilds both trees from the leaves and the state is taken only if the root
//! they make is the root it asked for. A piece that lies costs the receiver the
//! download, never a wrong state.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::cbor::{Reader, Writer};
use crate::error::{Error, Result};
use crate::id::NetworkId;
use crate::leaf::DeviceLeaf;
use crate::limits;
use crate::merkle::Hash;
use crate::parameters::Parameter;
use crate::state::RosterState;
use crate::types::NetworkParams;

/// Canonical key order of a state piece.
pub const STATE_PIECE_SCHEMA: &[&str] = &["devices", "parameters"];

/// Canonical key order of one parameter in a piece.
pub const PIECE_PARAMETER_SCHEMA: &[&str] = &["name", "value"];

/// The state cut into pieces of at most [`limits::MAX_STATE_PIECE_SIZE`]
/// bytes each.
///
/// The parameters travel in the first piece; the devices fill it and the
/// pieces after it, in the order of their ids.
#[must_use]
pub fn pieces_of(state: &RosterState) -> Vec<Vec<u8>> {
    let parameters: Vec<(&'static str, Vec<u8>)> =
        state.params.leaves().iter().map(|leaf| (leaf.name(), leaf.value_bytes())).collect();
    let leaves: Vec<Vec<u8>> = state
        .devices
        .keys()
        .filter_map(|device| state.leaf(device))
        .map(|leaf| leaf.to_bytes())
        .collect();

    let mut out = Vec::new();
    let mut current: Vec<Vec<u8>> = Vec::new();
    let mut current_size = 0_usize;
    let mut first = true;
    let budget = limits::MAX_STATE_PIECE_SIZE.saturating_sub(PIECE_OVERHEAD);
    let parameters_size: usize = parameters
        .iter()
        .map(|(name, value)| name.len().saturating_add(value.len()).saturating_add(16))
        .sum();

    let flush = |current: &mut Vec<Vec<u8>>, first: &mut bool, out: &mut Vec<Vec<u8>>| {
        let carried: &[(&'static str, Vec<u8>)] = if *first { &parameters } else { &[] };
        out.push(encode_piece(current, carried));
        current.clear();
        *first = false;
    };

    for leaf in leaves {
        let room = if first { budget.saturating_sub(parameters_size) } else { budget };
        let size = leaf.len().saturating_add(5);
        if !current.is_empty() && current_size.saturating_add(size) > room {
            flush(&mut current, &mut first, &mut out);
            current_size = 0;
        }
        current_size = current_size.saturating_add(size);
        current.push(leaf);
    }
    if !current.is_empty() || first {
        flush(&mut current, &mut first, &mut out);
    }
    out
}

/// Room kept in each piece for its framing.
const PIECE_OVERHEAD: usize = 64;

fn encode_piece(devices: &[Vec<u8>], parameters: &[(&'static str, Vec<u8>)]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.map(2);
    writer.key("devices").array(devices.len() as u64);
    for leaf in devices {
        writer.bytes(leaf);
    }
    writer.key("parameters").array(parameters.len() as u64);
    for (name, value) in parameters {
        writer.map(2);
        writer.key("name").str(name);
        writer.key("value").bytes(value);
    }
    writer.finish()
}

/// Gathers the pieces of a state and takes it only if it makes the root asked
/// for.
#[derive(Debug, Clone)]
pub struct StateAssembler {
    /// The network the state belongs to.
    network: NetworkId,
    /// The root the state must make.
    root: Hash,
    /// The device leaves so far, by id.
    devices: BTreeMap<crate::id::DeviceId, DeviceLeaf>,
    /// The parameter leaves so far.
    parameters: Vec<Parameter>,
    /// How many devices at most to accept: what the asker expects, bounding
    /// what a lying sender can make it hold.
    most: usize,
}

impl StateAssembler {
    /// Gathers a state of `network` that must make `root`, holding at most
    /// `most` devices.
    #[must_use]
    pub const fn new(network: NetworkId, root: Hash, most: usize) -> Self {
        Self { network, root, devices: BTreeMap::new(), parameters: Vec::new(), most }
    }

    /// Takes one piece.
    ///
    /// # Errors
    ///
    /// When the piece is larger than a piece may be, is not a canonical piece,
    /// repeats a device or a parameter already given, or brings the devices
    /// past the bound.
    pub fn add(&mut self, piece: &[u8]) -> Result<()> {
        if piece.len() > limits::MAX_STATE_PIECE_SIZE {
            return Err(Error::LimitExceeded("state piece size"));
        }
        let mut reader = Reader::new(piece);
        let mut map = reader.map(STATE_PIECE_SCHEMA)?;
        let devices = map.key("devices")?;
        let count = devices.array(limits::MAX_STATE_PIECE_SIZE, "state piece devices")?;
        for _ in 0..count {
            let leaf = DeviceLeaf::from_bytes(
                devices.bytes(limits::MAX_STATE_PIECE_SIZE, "device leaf size")?,
            )?;
            if self.devices.len() >= self.most {
                return Err(Error::LimitExceeded("state devices"));
            }
            if self.devices.insert(leaf.record.id, leaf).is_some() {
                return Err(Error::DuplicateKey);
            }
        }
        let parameters = map.key("parameters")?;
        let count = parameters.array(crate::parameters::PARAMETER_NAMES.len(), "parameters")?;
        for _ in 0..count {
            let mut entry = parameters.map(PIECE_PARAMETER_SCHEMA)?;
            let name =
                String::from(entry.key("name")?.str(limits::MAX_MAP_KEY_LEN, "parameter name")?);
            let value =
                entry.key("value")?.bytes(limits::MAX_STATE_PIECE_SIZE, "parameter size")?;
            entry.finish()?;
            let parameter = Parameter::decode(&name, value)?;
            if self.parameters.iter().any(|held| held.name() == parameter.name()) {
                return Err(Error::DuplicateKey);
            }
            self.parameters.push(parameter);
        }
        map.finish()?;
        reader.finish()
    }

    /// The state, once every piece is in and it makes the root asked for.
    ///
    /// # Errors
    ///
    /// When the parameters are incomplete, or the leaves make another root.
    pub fn finish(self) -> Result<RosterState> {
        let params = NetworkParams::from_leaves(self.parameters)?;
        let mut state = RosterState {
            network: self.network,
            params,
            devices: BTreeMap::new(),
            revoked: alloc::collections::BTreeSet::new(),
            settings: BTreeMap::new(),
        };
        for (device, leaf) in self.devices {
            state.devices.insert(device, leaf.record);
            state.set_settings(device, leaf.settings);
        }
        if state.root() != self.root {
            return Err(Error::SnapshotStateMismatch);
        }
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::is_canonical_schema;

    #[test]
    fn the_schemas_are_canonical() {
        assert!(is_canonical_schema(STATE_PIECE_SCHEMA));
        assert!(is_canonical_schema(PIECE_PARAMETER_SCHEMA));
    }
}

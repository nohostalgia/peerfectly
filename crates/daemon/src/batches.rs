//! A batch file, as an admin's daemon turns it into a batch to sign.
//!
//! The production station collected each board's public keys, serial and
//! proposed name (`bulk-admission`); the admin chooses the rest when admitting
//! — the label, the mode, the groups and the address block. Everything is
//! checked here before anything is shown: a batch the person reviews is the
//! batch that would be signed.
//!
//! The entries a batch would skip are read with `roster::batch::skipped`, the
//! one derivation applies, so what is shown and what happens cannot disagree.

use std::collections::BTreeSet;

use roster::batch::{BatchEntry, BatchHeader, Skip};
use roster::leaf::{Group, Mode};
use roster::state::RosterState;
use roster::types::{Algorithm, Ipv4Range, KeyEntry, KeyPurpose};

use crate::control::{BatchDevice, SkippedLine, shown};
use crate::service::BatchWanted;

/// The header and the entries of a batch of `devices`, as `wanted` asks, over
/// `state`: each entry's keys and name checked, and, where there is a block,
/// an address assigned to each from the block's hosts no member holds, in
/// device order.
///
/// # Errors
///
/// In words, when the label, a group, the block or an entry will not do.
pub(crate) fn prepared(
    state: &RosterState,
    devices: &[BatchDevice],
    wanted: &BatchWanted,
) -> Result<(BatchHeader, Vec<BatchEntry>), String> {
    let label = wanted.label.trim();
    if label.is_empty() {
        return Err("a batch needs a label: a line saying which lot it is".to_owned());
    }
    let mode = if wanted.light { Mode::Light } else { Mode::Full };
    let groups = wanted
        .groups
        .iter()
        .map(|group| {
            Group::new(group.clone())
                .map_err(|cause| format!("`{}` is not a group: {cause}", shown(group)))
        })
        .collect::<Result<Vec<Group>, String>>()?;
    let block = wanted
        .block
        .as_deref()
        .map(|block| {
            block
                .parse::<Ipv4Range>()
                .map_err(|cause| format!("`{}` is not an address block: {cause}", shown(block)))
        })
        .transpose()?;
    if let Some(block) = block {
        let range = state.params.ipv4_range();
        let last = last_address(&block);
        if !range.contains(block.address()) || !range.contains(last) {
            return Err(format!("the block {block} is outside the network's range, {range}"));
        }
    }

    let mut entries = Vec::with_capacity(devices.len());
    let mut seen = BTreeSet::new();
    for (line, device) in (1_u64..).zip(devices) {
        let key = |purpose: KeyPurpose, hex: &str| -> Result<KeyEntry, String> {
            let said = purpose.as_str();
            let bytes = hex::decode(hex.trim())
                .map_err(|_| format!("entry {line}: its {said} key is not hexadecimal"))?;
            KeyEntry::new(Algorithm::Ed25519, purpose, bytes)
                .map_err(|_| format!("entry {line}: its {said} key is not an Ed25519 public key"))
        };
        let mut keys = vec![
            key(KeyPurpose::Signing, &device.signing)?,
            key(KeyPurpose::Transport, &device.transport)?,
            key(KeyPurpose::Attestation, &device.attestation)?,
        ];
        keys.sort_by_key(KeyEntry::order_key);
        let name = crate::names::usable(&device.name)
            .map_err(|unusable| format!("entry {line}: {unusable}"))?;
        if device.serial.len() > roster::batch::MAX_SERIAL_LEN {
            return Err(format!(
                "entry {line}: its serial is longer than {} bytes",
                roster::batch::MAX_SERIAL_LEN
            ));
        }
        let entry = BatchEntry { keys, name, serial: device.serial.as_bytes().to_vec(), ipv4: None };
        let id = entry
            .device_id()
            .map_err(|cause| format!("entry {line}: {cause}"))?;
        if !seen.insert(id) {
            return Err(format!("entry {line} names a device another entry already names"));
        }
        entries.push(entry);
    }

    if let Some(block) = block {
        // In device order, as derivation judges them: of two entries that could
        // take one address, the smaller device has it, everywhere.
        entries.sort_by_key(|entry| entry.device_id().ok());
        let first = u32::from_be_bytes(block.address());
        let mut hosts = (1..block.size().saturating_sub(1))
            .filter_map(|offset| u32::try_from(offset).ok())
            .filter_map(|offset| first.checked_add(offset))
            .map(u32::to_be_bytes)
            .filter(|address| state.devices.holding_address(*address).is_empty());
        let count = entries.len();
        for entry in &mut entries {
            let Some(address) = hosts.next() else {
                return Err(format!(
                    "the block {block} has too few free addresses for {count} devices"
                ));
            };
            entry.ipv4 = Some(address);
        }
    }

    let header = BatchHeader::for_entries(&entries, mode, groups, block, label)
        .map_err(|cause| cause.to_string())?;
    Ok((header, entries))
}

/// The entries of a batch that would have no effect over `state`, and why, in
/// the batch's order.
pub(crate) fn skipped_lines(
    state: &RosterState,
    header: &BatchHeader,
    entries: &[BatchEntry],
) -> Vec<SkippedLine> {
    let skips = roster::batch::skipped(state, header, entries);
    entries
        .iter()
        .filter_map(|entry| {
            let why = skips.get(&entry.device_id().ok()?)?;
            Some(SkippedLine { name: entry.name.clone(), why: said(*why).to_owned() })
        })
        .collect()
}

/// Why an entry is skipped, in words.
const fn said(skip: Skip) -> &'static str {
    match skip {
        Skip::AlreadyMember => "already a member of the network",
        Skip::AddressOutsideBlock => "its address is outside the block",
        Skip::AddressTaken => "its address is held by another device",
    }
}

/// A block's last address.
fn last_address(block: &Ipv4Range) -> [u8; 4] {
    let first = u64::from(u32::from_be_bytes(block.address()));
    let last = first.saturating_add(block.size()).saturating_sub(1);
    u32::try_from(last).unwrap_or(u32::MAX).to_be_bytes()
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use identity::NodeIdentity;
    use roster::id::NetworkId;
    use roster::types::NetworkParams;

    use super::*;

    fn device(name: &str) -> BatchDevice {
        let board = NodeIdentity::generate().unwrap();
        let spec = board.device_spec(name, roster::types::Role::Member, false, vec![]).unwrap();
        let hex_of = |purpose: KeyPurpose| {
            spec.keys
                .iter()
                .find(|entry| entry.purpose == purpose)
                .map(|entry| hex::encode(&entry.value))
                .unwrap()
        };
        BatchDevice {
            name: name.to_owned(),
            serial: format!("SN-{name}"),
            signing: hex_of(KeyPurpose::Signing),
            transport: hex_of(KeyPurpose::Transport),
            attestation: hex_of(KeyPurpose::Attestation),
        }
    }

    fn state() -> RosterState {
        let params =
            NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 0).unwrap();
        RosterState::from_parts(
            NetworkId::from_bytes([7; 32]),
            params,
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeMap::new(),
        )
    }

    fn wanted(block: Option<&str>) -> BatchWanted {
        BatchWanted {
            label: "lot A".to_owned(),
            light: true,
            groups: vec!["sensori".to_owned()],
            block: block.map(str::to_owned),
        }
    }

    #[test]
    fn a_batch_is_prepared_with_an_address_each_from_its_block() {
        let devices: Vec<BatchDevice> = (0..5).map(|n| device(&format!("board-{n}"))).collect();
        let (header, entries) = prepared(&state(), &devices, &wanted(Some("100.64.9.0/28"))).unwrap();
        assert_eq!(header.count, 5);
        assert_eq!(header.mode, Mode::Light);
        let addresses: BTreeSet<[u8; 4]> = entries.iter().filter_map(|entry| entry.ipv4).collect();
        assert_eq!(addresses.len(), 5, "an address each, none repeated");
        assert!(!addresses.contains(&[100, 64, 9, 0]) && !addresses.contains(&[100, 64, 9, 15]));
        assert!(skipped_lines(&state(), &header, &entries).is_empty());
    }

    #[test]
    fn a_batch_that_will_not_do_is_refused_in_words() {
        // Fifteen devices, for a block of fourteen hosts.
        let devices: Vec<BatchDevice> = (0..15).map(|n| device(&format!("board-{n}"))).collect();
        let outside = prepared(&state(), &devices, &wanted(Some("192.168.1.0/24"))).unwrap_err();
        assert!(outside.contains("outside the network's range"), "{outside}");
        let small = prepared(&state(), &devices, &wanted(Some("100.64.9.0/28"))).unwrap_err();
        assert!(small.contains("too few free addresses"), "{small}");

        let mut forged = device("board");
        forged.transport = "not hex".to_owned();
        let refused = prepared(&state(), &[forged], &wanted(None)).unwrap_err();
        assert!(refused.contains("entry 1") && refused.contains("transport"), "{refused}");

        let twice = device("board");
        let refused = prepared(&state(), &[twice.clone(), twice], &wanted(None)).unwrap_err();
        assert!(refused.contains("another entry"), "{refused}");

        let mut unlabelled = wanted(None);
        unlabelled.label = "  ".to_owned();
        assert!(prepared(&state(), &[device("board")], &unlabelled).unwrap_err().contains("label"));
    }
}

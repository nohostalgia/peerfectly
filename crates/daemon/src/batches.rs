//! A batch file, as an admin's daemon turns it into a batch to sign.
//!
//! The production station collected each board's public keys, serial and
//! proposed name (`bulk-admission`); the admin chooses the rest when admitting
//! — the label, the mode, the groups, and whether the boards hold IPv4. Every
//! check is made here before anything is shown: a batch the person reviews is
//! the batch that would be signed.
//!
//! The entries a batch would skip are read with `roster::batch::skipped`, the
//! one derivation applies, so what is shown and what happens cannot disagree.

use std::collections::BTreeSet;

use roster::batch::{BatchEntry, BatchHeader, OffsetRun, Skip};
use roster::leaf::{Group, Mode};
use roster::state::RosterState;
use roster::types::{Algorithm, Ipv4Range, KeyEntry, KeyPurpose};

use crate::control::{BatchDevice, SkippedLine, shown};
use crate::service::BatchWanted;

/// The header and the entries of a batch of `devices`, as `wanted` asks, over
/// `state`: each entry's keys and name checked, and, unless the boards are
/// admitted IPv6 only, an offset given each from the lowest run of the
/// network's block that no member holds and is long enough, in device order
/// (`scalable-membership` 19.2).
///
/// # Errors
///
/// In words, when the label, a group or an entry will not do, or the block has
/// no run long enough.
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
        let entry =
            BatchEntry { keys, name, serial: device.serial.as_bytes().to_vec(), ipv4: None };
        let id = entry.device_id().map_err(|cause| format!("entry {line}: {cause}"))?;
        if !seen.insert(id) {
            return Err(format!("entry {line} names a device another entry already names"));
        }
        entries.push(entry);
    }

    let offsets = if wanted.ipv6_only {
        None
    } else {
        // In device order, as derivation judges them.
        entries.sort_by_key(|entry| entry.device_id().ok());
        let count = u32::try_from(entries.len()).unwrap_or(u32::MAX);
        let range = state.params.ipv4_range();
        let first = state.free_offsets(count).ok_or_else(|| {
            format!(
                "the network's block, {range}, has no {count} consecutive free addresses. Grow                  the block, or admit these devices IPv6 only (--ipv6-only)"
            )
        })?;
        let run = OffsetRun::new(first, count).map_err(|cause| cause.to_string())?;
        for (entry, offset) in entries.iter_mut().zip(run.offsets()) {
            entry.ipv4 = Some(offset);
        }
        Some(run)
    };

    let header = BatchHeader::for_entries(&entries, mode, groups, offsets, label)
        .map_err(|cause| cause.to_string())?;
    Ok((header, entries))
}

/// The addresses a run of offsets names in `range`, first to last, as a person
/// reads them.
pub(crate) fn addresses_of(range: &Ipv4Range, run: &OffsetRun) -> String {
    let at = |offset| {
        range.address_at(offset).map_or_else(
            || format!("offset {}", u32::from_be_bytes(offset)),
            |address| std::net::Ipv4Addr::from(address).to_string(),
        )
    };
    if run.count() == 1 {
        at(run.first())
    } else {
        format!("{} to {}", at(run.first()), at(run.last()))
    }
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
        Skip::OffsetOutsideRun => "its address is outside the batch's addresses",
        Skip::OffsetTaken => "its address is held by another device",
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use std::collections::BTreeSet;

    use identity::NodeIdentity;
    use roster::id::{DeviceId, NetworkId};
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

    /// A network in `block` whose founder holds the first host.
    fn state_in(block: &str) -> RosterState {
        let params = NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 0)
            .unwrap()
            .in_ipv4_range(block.parse().unwrap());
        let founder = DeviceId::from_bytes([1; 32]);
        let record = roster::types::DeviceRecord {
            id: founder,
            keys: Vec::new(),
            name: "nas".to_owned(),
            role: roster::types::Role::Admin,
            founder: true,
            added_by: roster::id::OperationId::from_bytes([0; 32]),
            capabilities: Vec::new(),
        };
        let settings = roster::leaf::DeviceSettings {
            ipv4: Some(roster::leaf::FIRST_HOST),
            ..roster::leaf::DeviceSettings::default()
        };
        RosterState::from_parts(
            NetworkId::from_bytes([7; 32]),
            params,
            [(founder, record)].into_iter().collect(),
            BTreeSet::new(),
            [(founder, settings)].into_iter().collect(),
        )
    }

    fn state() -> RosterState {
        state_in("100.64.0.0/10")
    }

    fn wanted(ipv6_only: bool) -> BatchWanted {
        BatchWanted {
            label: "lot A".to_owned(),
            light: true,
            groups: vec!["sensori".to_owned()],
            ipv6_only,
        }
    }

    #[test]
    fn a_batch_is_given_the_lowest_free_run_in_device_order() {
        let devices: Vec<BatchDevice> = (0..5).map(|n| device(&format!("board-{n}"))).collect();
        let (header, entries) = prepared(&state(), &devices, &wanted(false)).unwrap();
        assert_eq!(header.count, 5);
        assert_eq!(header.mode, Mode::Light);
        let run = header.offsets.expect("a run");
        assert_eq!((run.first(), run.count()), (2_u32.to_be_bytes(), 5), "after the founder's");
        let given: Vec<u32> =
            entries.iter().filter_map(|entry| entry.ipv4.map(u32::from_be_bytes)).collect();
        assert_eq!(given, [2, 3, 4, 5, 6], "consecutive, in the entries' order");
        let ids: Vec<DeviceId> = entries.iter().map(|entry| entry.device_id().unwrap()).collect();
        assert!(ids.is_sorted(), "which is device order");
        assert!(skipped_lines(&state(), &header, &entries).is_empty());
        assert_eq!(addresses_of(&state().params.ipv4_range(), &run), "100.64.0.2 to 100.64.0.6");
    }

    #[test]
    fn a_batch_admitted_ipv6_only_takes_no_offsets() {
        let devices: Vec<BatchDevice> = (0..3).map(|n| device(&format!("board-{n}"))).collect();
        let (header, entries) = prepared(&state(), &devices, &wanted(true)).unwrap();
        assert_eq!(header.offsets, None);
        assert!(entries.iter().all(|entry| entry.ipv4.is_none()));
    }

    #[test]
    fn a_batch_that_will_not_do_is_refused_in_words() {
        // Fourteen devices, for a block of fourteen hosts the founder holds one of.
        let devices: Vec<BatchDevice> = (0..14).map(|n| device(&format!("board-{n}"))).collect();
        let small = prepared(&state_in("10.0.0.0/28"), &devices, &wanted(false)).unwrap_err();
        assert!(
            small.contains("no 14 consecutive free") && small.contains("--ipv6-only"),
            "{small}"
        );
        assert!(prepared(&state_in("10.0.0.0/28"), &devices, &wanted(true)).is_ok());

        let mut forged = device("board");
        forged.transport = "not hex".to_owned();
        let refused = prepared(&state(), &[forged], &wanted(false)).unwrap_err();
        assert!(refused.contains("entry 1") && refused.contains("transport"), "{refused}");

        let twice = device("board");
        let refused = prepared(&state(), &[twice.clone(), twice], &wanted(false)).unwrap_err();
        assert!(refused.contains("another entry"), "{refused}");

        let mut unlabelled = wanted(false);
        unlabelled.label = "  ".to_owned();
        assert!(prepared(&state(), &[device("board")], &unlabelled).unwrap_err().contains("label"));
    }
}

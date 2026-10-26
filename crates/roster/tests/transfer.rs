//! A whole state, sent in pieces to a member that holds nothing yet.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod support;

use std::collections::{BTreeMap, BTreeSet};

use roster::id::{NetworkId, OperationId};
use roster::leaf::{DeviceSettings, Group, Mode};
use roster::limits::MAX_STATE_PIECE_SIZE;
use roster::sign::{Ed25519Signer, Signer as _};
use roster::state::RosterState;
use roster::transfer::{StateAssembler, pieces_of};
use roster::types::{Algorithm, DeviceSpec, KeyEntry, KeyPurpose, Role};
use support::params;

/// A state of `count` devices, every fifth light and in a group.
fn state_of(count: u32) -> RosterState {
    let mut state = RosterState::from_parts(NetworkId::from_bytes([7; 32]), params(), BTreeMap::new(), BTreeSet::new(), BTreeMap::new());
    for index in 0..count {
        let mut seed = [0_u8; 32];
        seed[..4].copy_from_slice(&index.to_be_bytes());
        let signing = Ed25519Signer::from_seed(seed);
        seed[4] = 1;
        let attesting = Ed25519Signer::from_seed(seed);
        let mut keys = vec![
            KeyEntry::new(
                Algorithm::Ed25519,
                KeyPurpose::Signing,
                signing.public_key().as_bytes().to_vec(),
            )
            .unwrap(),
            KeyEntry::new(
                Algorithm::Ed25519,
                KeyPurpose::Attestation,
                attesting.public_key().as_bytes().to_vec(),
            )
            .unwrap(),
        ];
        keys.sort_by_key(KeyEntry::order_key);
        let record = DeviceSpec::new(keys, format!("sensor-{index}"), Role::Member, false, vec![])
            .unwrap()
            .into_record(OperationId::from_bytes([1; 32]))
            .unwrap();
        let device = record.id;
        state.devices.insert(device, record);
        if index % 5 == 0 {
            state.set_settings(
                device,
                DeviceSettings::new(Mode::Light, vec![Group::new("sensori").unwrap()], None, None)
                    .unwrap(),
            );
        }
    }
    state
}

/// Sends `state` through its pieces and returns what the receiver made of it.
fn sent(state: &RosterState) -> RosterState {
    let pieces = pieces_of(state);
    let mut assembler = StateAssembler::new(state.network, state.root(), state.devices.len());
    for piece in &pieces {
        assert!(piece.len() <= MAX_STATE_PIECE_SIZE, "a piece of {} bytes", piece.len());
        assembler.add(piece).unwrap();
    }
    assembler.finish().unwrap()
}

#[test]
fn a_state_arrives_whole_in_pieces_within_the_limits() {
    let state = state_of(2_000);
    let received = sent(&state);
    assert_eq!(received.to_bytes(), state.to_bytes());
    assert_eq!(received.root(), state.root());
    assert!(pieces_of(&state).len() > 1, "more than one piece");
}

#[test]
fn an_empty_network_is_one_piece() {
    let state = state_of(0);
    assert_eq!(pieces_of(&state).len(), 1);
    assert_eq!(sent(&state).root(), state.root());
}

#[test]
fn a_piece_that_lies_is_found_out_at_the_end() {
    let state = state_of(300);
    let honest = pieces_of(&state);
    // The sender drops one device: every piece decodes, and the root is wrong.
    let fewer = {
        let mut smaller = state.clone();
        let first = smaller.devices.keys().next().unwrap();
        smaller.devices.remove(&first);
        pieces_of(&smaller)
    };
    let mut assembler = StateAssembler::new(state.network, state.root(), state.devices.len());
    for piece in &fewer {
        assembler.add(piece).unwrap();
    }
    assert!(assembler.finish().is_err(), "a state missing a device makes another root");

    // The same device twice is refused as it arrives.
    let mut assembler = StateAssembler::new(state.network, state.root(), state.devices.len());
    let first = honest.first().unwrap();
    assembler.add(first).unwrap();
    assert!(assembler.add(first).is_err());
}

#[test]
fn a_sender_cannot_make_the_receiver_hold_more_than_it_asked_for() {
    let state = state_of(300);
    let mut assembler = StateAssembler::new(state.network, state.root(), 10);
    let refused = pieces_of(&state).iter().any(|piece| assembler.add(piece).is_err());
    assert!(refused, "past the bound the receiver set");
}

#[test]
#[ignore = "long: a hundred thousand devices, run deliberately"]
fn a_hundred_thousand_devices_arrive_in_pieces_within_the_limits() {
    let state = state_of(100_000);
    let received = sent(&state);
    assert_eq!(received.root(), state.root());
}

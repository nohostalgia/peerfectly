//! Telling a revoked device, and being told (offline-founder design §16).
//!
//! The transport admits a device held as revoked only to refuse it as revoked
//! and send it its revocation, and carries a notice to a device outside any
//! session; this is what it is told, and how what it hears is judged. Kept out
//! of the node, which assembles and decides nothing about membership: whether a
//! revocation holds is the roster's, read here through the state the node gives.

use std::collections::BTreeMap;

use roster::id::DeviceId;

use crate::node::Node;

/// The devices this node holds as revoked, each by the transport key it was
/// admitted with, with the revocation that names it: what the transport
/// admits only to refuse as revoked and tell (offline-founder design §16).
///
/// Only while the revocation is held: once compacted away, the device is a
/// stranger, as everywhere else. A device admitted in a batch is a light
/// member, which is told by the roots it follows, and is not here.
pub async fn revoked_peers(node: &Node) -> BTreeMap<DeviceId, transport::session::Revoked> {
    let Ok(state) = node.state().await else { return BTreeMap::new() };
    if state.revoked.is_empty() {
        return BTreeMap::new();
    }
    let Some((held, _)) = node.held_with_verdicts().await else { return BTreeMap::new() };
    let mut keys: BTreeMap<DeviceId, Vec<u8>> = BTreeMap::new();
    for (operation, _) in &held {
        let spec = match operation.body() {
            roster::types::OperationBody::AddDevice(spec) => spec,
            roster::types::OperationBody::CreateNetwork { device, .. } => device,
            _ => continue,
        };
        let Ok(device) = spec.device_id() else { continue };
        if let Some(entry) =
            spec.keys.iter().find(|entry| entry.purpose == roster::types::KeyPurpose::Transport)
        {
            keys.insert(device, entry.value.clone());
        }
    }
    held.iter()
        .filter(|(_, verdict)| verdict.is_none())
        .filter_map(|(operation, _)| {
            let roster::types::OperationBody::RevokeDevice { device, .. } = operation.body() else {
                return None;
            };
            if !state.revoked.contains(device) {
                return None;
            }
            Some((
                *device,
                transport::session::Revoked {
                    transport: keys.get(device)?.clone(),
                    revocation: operation.to_bytes(),
                },
            ))
        })
        .collect()
}

/// Who signed `notice`, where it is a revocation of this device that this
/// node can verify: signed by the founder key the roster holds, or, for a
/// member, by an admin it holds (offline-founder design §16). `None` for
/// anything else, which is ignored.
///
/// Only the founder revokes an admin, so an admin's revocation of this
/// device, when it is an admin here, is no revocation.
pub async fn judged(node: &Node, notice: &[u8]) -> Option<String> {
    let raw = roster::sign::RawOperation::decode(notice).ok()?;
    let roster::types::OperationBody::RevokeDevice { device, .. } = &raw.core().body else {
        return None;
    };
    let me = node.identity().device_id();
    if *device != me {
        return None;
    }
    let state = node.state().await.ok()?;
    if raw.core().network != state.network {
        return None;
    }
    let author = raw.core().author;
    let (key, by) = if author == state.params.founder.signing_id() {
        let key = roster::sign::PublicKey::new(
            roster::types::Algorithm::Ed25519,
            state.params.founder.signing().to_vec(),
        )
        .ok()?;
        (key, "the founder".to_owned())
    } else {
        if state.is_admin(&me) {
            return None;
        }
        let leaf = state.device_for_key(&author)?;
        if leaf.record.role != roster::types::Role::Admin {
            return None;
        }
        let entry = leaf.record.keys.iter().find(|entry| {
            entry.purpose == roster::types::KeyPurpose::Signing && entry.key_id() == author
        })?;
        let key = roster::sign::PublicKey::new(entry.alg, entry.value.clone()).ok()?;
        (key, format!("{} [{}]", leaf.record.name, crate::control::short_id(&leaf.record.id)))
    };
    raw.verify(&key).ok()?;
    Some(by)
}

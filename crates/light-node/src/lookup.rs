//! Finding a member by name or address, for a device holding no roster.
//!
//! A light member asks; any full member answers with the device's evidence —
//! its leaf, the proof of it and the root they rest on — or with nothing. The
//! asker believes the answer only if it holds up on its own: the proof leads
//! to a root it believes, and the leaf is the one the question named. So any
//! member may answer, and none can answer falsely.
//!
//! # On the wire
//!
//! On the session's lookup channel:
//!
//! ```text
//! REQUEST  1 | id: u32 BE | query
//! ANSWER   2 | id: u32 BE | evidence      (empty: nothing known)
//!
//! query = 1 | name (UTF-8)  /  2 | IPv6 (16 bytes)  /  3 | IPv4 (4 bytes)
//!       / 4 | root (32 bytes)  /  5 | device id (32 bytes)
//! ```
//!
//! The fourth asks for the roots taken after one: the chain a light member
//! that missed some needs. Its answer is the roots, oldest first, each preceded
//! by its length as a big-endian `u32`.
//!
//! The fifth asks what the light member with that id stands on: the network's
//! parameters, with the root of the devices' tree beside them — the two make
//! the state root, which the asker holds signed — and the evidence of the full
//! members it may turn to, as `seeking::handed` chooses them. Its answer is
//! the devices' root (32 bytes), the parameters preceded by their length as a
//! big-endian `u32`, then the evidences as the roots are carried.
//!
//! Decoding never panics: anything that is not one of these is refused whole.

use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

use roster::id::DeviceId;
use roster::leaf::DeviceLeaf;

/// What is asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// The member going by this name.
    Name(String),
    /// The member holding this overlay IPv6 address.
    Ipv6(Ipv6Addr),
    /// The member holding this IPv4 address.
    Ipv4(Ipv4Addr),
    /// The roots taken after this one, for a member that missed them.
    RootsAfter([u8; 32]),
    /// What the light member with this id stands on: the parameters, and the
    /// full members it may turn to. With the [`Footing::digest`] of the
    /// footing it last took, where it holds one: a footing that has not
    /// changed is answered with that digest alone.
    Footing(DeviceId, Option<[u8; 32]>),
}

/// A lookup message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A question, with the id its answer will carry.
    Request {
        /// The id.
        id: u32,
        /// What is asked.
        query: Query,
    },
    /// An answer: the evidence of the member asked for, or nothing.
    Answer {
        /// The id of the question.
        id: u32,
        /// `roster::membership::Evidence` bytes, or empty.
        evidence: Vec<u8>,
    },
}

const REQUEST: u8 = 1;
const ANSWER: u8 = 2;
const BY_NAME: u8 = 1;
const BY_IPV6: u8 = 2;
const BY_IPV4: u8 = 3;
const ROOTS_AFTER: u8 = 4;
const FOOTING: u8 = 5;

impl Message {
    /// Its bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Request { id, query } => {
                out.push(REQUEST);
                out.extend_from_slice(&id.to_be_bytes());
                match query {
                    Query::Name(name) => {
                        out.push(BY_NAME);
                        out.extend_from_slice(name.as_bytes());
                    }
                    Query::Ipv6(address) => {
                        out.push(BY_IPV6);
                        out.extend_from_slice(&address.octets());
                    }
                    Query::Ipv4(address) => {
                        out.push(BY_IPV4);
                        out.extend_from_slice(&address.octets());
                    }
                    Query::RootsAfter(root) => {
                        out.push(ROOTS_AFTER);
                        out.extend_from_slice(root);
                    }
                    Query::Footing(device, held) => {
                        out.push(FOOTING);
                        out.extend_from_slice(device.as_bytes());
                        if let Some(held) = held {
                            out.extend_from_slice(held);
                        }
                    }
                }
            }
            Self::Answer { id, evidence } => {
                out.push(ANSWER);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(evidence);
            }
        }
        out
    }

    /// Reads a message, or `None` for anything that is not one.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&kind, rest) = bytes.split_first()?;
        let (id, rest) = rest.split_at_checked(4)?;
        let id = u32::from_be_bytes(id.try_into().ok()?);
        match kind {
            REQUEST => {
                let (&by, value) = rest.split_first()?;
                let query = match by {
                    BY_NAME => {
                        let name = core::str::from_utf8(value).ok()?;
                        if name.is_empty() || name.len() > roster::limits::MAX_NAME_LEN {
                            return None;
                        }
                        Query::Name(name.to_owned())
                    }
                    BY_IPV6 => Query::Ipv6(Ipv6Addr::from(<[u8; 16]>::try_from(value).ok()?)),
                    BY_IPV4 => Query::Ipv4(Ipv4Addr::from(<[u8; 4]>::try_from(value).ok()?)),
                    ROOTS_AFTER => Query::RootsAfter(<[u8; 32]>::try_from(value).ok()?),
                    FOOTING => {
                        let (device, held) = value.split_at_checked(32)?;
                        let device = DeviceId::from_bytes(<[u8; 32]>::try_from(device).ok()?);
                        let held = match held.len() {
                            0 => None,
                            _ => Some(<[u8; 32]>::try_from(held).ok()?),
                        };
                        Query::Footing(device, held)
                    }
                    _ => return None,
                };
                Some(Self::Request { id, query })
            }
            ANSWER => Some(Self::Answer { id, evidence: rest.to_vec() }),
            _ => None,
        }
    }
}

/// The most bytes of roots a lookup answer carries: within the least frame
/// every end of a session takes (`transport_wire::frame::Limits::LEAST`, 72
/// KiB) with the frame's, the channel's and the answer's headers beside them,
/// and room for a root of the largest size. A member that missed more takes
/// what came, and asks again from there.
pub const MAX_ROOTS_ANSWER: usize = 70 * 1_024;

const _: () = assert!(
    MAX_ROOTS_ANSWER >= roster::limits::MAX_SNAPSHOT_SIZE + 4,
    "a root of the largest size fits one answer"
);

/// Roots, as an answer carries them.
#[must_use]
pub fn encode_roots(roots: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for root in roots {
        out.extend_from_slice(&u32::try_from(root.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(root);
    }
    out
}

/// [`encode_roots`], of as many roots from the oldest as fit in `room` bytes,
/// whole: a light member takes what came, and asks again from there.
#[must_use]
pub fn encode_roots_within(roots: &[Vec<u8>], room: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for root in roots {
        if out.len().saturating_add(4).saturating_add(root.len()) > room {
            break;
        }
        out.extend_from_slice(&u32::try_from(root.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(root);
    }
    out
}

/// Roots, read back from an answer; `None` for anything that is not a list of
/// them.
#[must_use]
pub fn decode_roots(mut bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut roots = Vec::new();
    while !bytes.is_empty() {
        let (length, rest) = bytes.split_at_checked(4)?;
        let length = usize::try_from(u32::from_be_bytes(length.try_into().ok()?)).ok()?;
        if length > roster::limits::MAX_SNAPSHOT_SIZE {
            return None;
        }
        let (root, rest) = rest.split_at_checked(length)?;
        roots.push(root.to_vec());
        bytes = rest;
    }
    Some(roots)
}

/// Whether `leaf` is the member `query` asks for, in a network with these
/// parameters: checked by the asker, from the leaf alone.
#[must_use]
pub fn answers(query: &Query, leaf: &DeviceLeaf, params: &roster::types::NetworkParams) -> bool {
    let device = leaf.record.id;
    match query {
        Query::Name(name) => leaf.record.name.eq_ignore_ascii_case(name),
        Query::Ipv6(address) => tunnel::Prefix::from_parameter(&params.ula)
            .is_ok_and(|prefix| tunnel::address_of(&device, &prefix) == *address),
        // The address its offset names in the network's block; a device given
        // none answers for no IPv4 address.
        Query::Ipv4(address) => leaf
            .settings
            .ipv4
            .and_then(|offset| params.ipv4_range().address_at(offset))
            .is_some_and(|held| Ipv4Addr::from(held) == *address),
        Query::RootsAfter(_) | Query::Footing(..) => false,
    }
}

/// What a light member stands on, as a footing answer carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Footing {
    /// The root of the devices' tree under the root the answer rests on.
    pub devices_root: [u8; 32],
    /// The network's parameters under it, as bytes.
    pub params: Vec<u8>,
    /// The evidence of each full member handed over.
    pub fulls: Vec<Vec<u8>>,
}

/// The context a footing's digest is derived under.
const FOOTING_DIGEST_CONTEXT: &str = "peerfectly footing digest v1";

impl Footing {
    /// What a light member keeps of it, as one hash: the parameters, and the
    /// leaf of each full member handed over. Not the devices' root nor the
    /// proofs, which change with every root: a footing whose digest is the one
    /// a light member last took holds nothing it lacks.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(FOOTING_DIGEST_CONTEXT);
        hasher.update(&u64::try_from(self.params.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(&self.params);
        for full in &self.fulls {
            match roster::membership::Evidence::from_bytes(full) {
                Ok(shown) => hasher.update(&shown.leaf.value_hash()),
                Err(_) => hasher.update(&blake3::hash(full).as_bytes()[..]),
            };
        }
        *hasher.finalize().as_bytes()
    }

    /// Its bytes, as an answer carries them.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.devices_root);
        out.extend_from_slice(&u32::try_from(self.params.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(&self.params);
        out.extend_from_slice(&encode_roots(&self.fulls));
        out
    }

    /// Reads one back; `None` for anything that is not one.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (devices_root, rest) = bytes.split_at_checked(32)?;
        let (length, rest) = rest.split_at_checked(4)?;
        let length = usize::try_from(u32::from_be_bytes(length.try_into().ok()?)).ok()?;
        if length > roster::limits::MAX_SNAPSHOT_SIZE {
            return None;
        }
        let (params, rest) = rest.split_at_checked(length)?;
        Some(Self {
            devices_root: devices_root.try_into().ok()?,
            params: params.to_vec(),
            fulls: decode_roots(rest)?,
        })
    }
}

/// Takes what a full member handed over as `footing`: the parameters, where
/// they make the root this member holds, and each full member whose evidence
/// holds. Whether anything this member keeps changed.
///
/// Nothing is believed on the word of whoever sent it: parameters that do not
/// make the signed root are left aside, and evidence that does not hold is
/// not kept.
pub fn take_footing(member: &mut roster::member::LightMember, footing: &Footing) -> bool {
    let mut changed = false;
    if let Ok(params) = roster::types::NetworkParams::from_bytes(&footing.params) {
        changed |= member.take_params(&footing.devices_root, params).unwrap_or(false);
    }
    for evidence in &footing.fulls {
        let Ok(shown) = roster::membership::Evidence::from_bytes(evidence) else { continue };
        if shown.leaf.settings.mode != roster::leaf::Mode::Full {
            continue;
        }
        changed |= member.learn(evidence).is_ok();
    }
    changed
}

/// Why an answer was not believed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Nothing was known.
    Unknown,
    /// The leaf is not the member asked for.
    NotAsked,
    /// The evidence does not hold, or rests on a root not believed.
    NotProved(String),
}

/// Checks an answer to `query` and, where it holds, learns the member.
///
/// # Errors
///
/// When nothing was answered, the leaf is not the one asked for, or the
/// evidence does not hold for `member`.
pub fn take_answer(
    member: &mut roster::member::LightMember,
    query: &Query,
    evidence: &[u8],
) -> Result<DeviceId, Refusal> {
    if evidence.is_empty() {
        return Err(Refusal::Unknown);
    }
    let shown = roster::membership::Evidence::from_bytes(evidence)
        .map_err(|cause| Refusal::NotProved(cause.to_string()))?;
    if !answers(query, &shown.leaf, member.params()) {
        return Err(Refusal::NotAsked);
    }
    member.learn(evidence).map_err(|cause| Refusal::NotProved(cause.to_string()))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn messages_read_back_as_written() {
        for message in [
            Message::Request { id: 7, query: Query::Name("phone".into()) },
            Message::Request { id: 8, query: Query::Ipv6(Ipv6Addr::LOCALHOST) },
            Message::Request { id: 9, query: Query::Ipv4(Ipv4Addr::new(100, 64, 0, 1)) },
            Message::Answer { id: 10, evidence: vec![1, 2, 3] },
            Message::Answer { id: 11, evidence: Vec::new() },
            Message::Request { id: 12, query: Query::RootsAfter([3; 32]) },
        ] {
            assert_eq!(Message::decode(&message.encode()), Some(message));
        }
        assert_eq!(Message::decode(&[REQUEST, 0, 0, 0, 1, BY_IPV4, 1, 2]), None);
    }
}

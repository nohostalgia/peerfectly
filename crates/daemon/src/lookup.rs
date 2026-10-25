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
//!       / 4 | root (32 bytes)
//! ```
//!
//! The fourth asks for the roots taken after one: the chain a light member
//! that missed some needs. Its answer is the roots, oldest first, each preceded
//! by its length as a big-endian `u32`.
//!
//! Decoding never panics: anything that is not one of these is refused whole.

use std::net::{Ipv4Addr, Ipv6Addr};

use roster::id::DeviceId;
use roster::leaf::DeviceLeaf;
use roster::state::RosterState;

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
                    _ => return None,
                };
                Some(Self::Request { id, query })
            }
            ANSWER => Some(Self::Answer { id, evidence: rest.to_vec() }),
            _ => None,
        }
    }
}

/// The member a full member's state names for `query`, if any.
#[must_use]
pub fn resolve(state: &RosterState, query: &Query) -> Option<DeviceId> {
    match query {
        Query::Name(name) => state
            .devices
            .values()
            .find(|record| record.name.eq_ignore_ascii_case(name))
            .map(|record| record.id),
        Query::Ipv6(address) => {
            let prefix = tunnel::Prefix::from_parameter(&state.params.ula).ok()?;
            state
                .devices
                .keys()
                .find(|device| tunnel::address_of(device, &prefix) == *address)
                .copied()
        }
        Query::Ipv4(address) => tunnel::Ipv4Holdings::of_state(state).holder(*address),
        Query::RootsAfter(_) => None,
    }
}

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
pub fn answers(
    query: &Query,
    leaf: &DeviceLeaf,
    network: &roster::id::NetworkId,
    params: &roster::types::NetworkParams,
) -> bool {
    let device = leaf.record.id;
    match query {
        Query::Name(name) => leaf.record.name.eq_ignore_ascii_case(name),
        Query::Ipv6(address) => tunnel::Prefix::from_parameter(&params.ula)
            .is_ok_and(|prefix| tunnel::address_of(&device, &prefix) == *address),
        Query::Ipv4(address) => match leaf.settings.ipv4 {
            Some(assigned) => Ipv4Addr::from(assigned) == *address,
            None => tunnel::ipv4_candidate(network, &device, &params.ipv4_range()) == *address,
        },
        Query::RootsAfter(_) => false,
    }
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
    if !answers(query, &shown.leaf, &member.network(), member.params()) {
        return Err(Refusal::NotAsked);
    }
    member.learn(evidence).map_err(|cause| Refusal::NotProved(cause.to_string()))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use identity::NodeIdentity;
    use roster::id::NetworkId;
    use roster::member::{DEFAULT_BUDGET, LightMember};
    use roster::roster::Roster;
    use roster::sign::sign_operation;
    use roster::types::{NetworkParams, OperationBody, OperationCore, Role};

    use super::*;

    /// A founder's roster of three members, with a root over it, and the three.
    fn rooted() -> (Roster, Vec<NodeIdentity>) {
        let founder = NodeIdentity::generate().unwrap();
        let params =
            NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 2_592_000)
                .unwrap();
        let mut roster = Roster::new();
        let mut parents = Vec::new();
        let mut network = NetworkId::from_bytes([0; 32]);
        let members: Vec<NodeIdentity> =
            (0..3).map(|_| NodeIdentity::generate().unwrap()).collect();
        let bodies = std::iter::once(OperationBody::CreateNetwork {
            device: founder.device_spec("nas", Role::Admin, true, vec![]).unwrap(),
            params,
        })
        .chain(members.iter().zip(["laptop", "phone", "sensor"]).map(|(member, name)| {
            OperationBody::AddDevice(member.device_spec(name, Role::Member, false, vec![]).unwrap())
        }));
        for (index, body) in bodies.enumerate() {
            let core = OperationCore::new(
                u64::try_from(index).unwrap().saturating_add(1),
                founder.signing_key().algorithm(),
                body,
                parents.clone(),
                founder.signing_key().key_id(),
                network,
            )
            .unwrap();
            if index == 0 {
                network = NetworkId::from_bytes(*core.id().as_bytes());
            }
            parents = vec![core.id()];
            assert!(
                roster.offer_bytes(&sign_operation(&core, founder.signer()).unwrap()).is_accepted()
            );
        }
        let root = crate::snapshots::sign_over_heads(&roster, &founder).unwrap();
        assert!(roster.offer_snapshot(&root).is_accepted());
        (roster, members)
    }

    fn light_for(roster: &Roster, device: &DeviceId) -> LightMember {
        LightMember::new(
            roster.evidence_for(device).unwrap(),
            roster.state().unwrap().params,
            DEFAULT_BUDGET,
        )
        .unwrap()
    }

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

    #[test]
    fn a_full_member_resolves_by_name_ipv6_and_ipv4_and_a_light_one_believes_it() {
        let (roster, members) = rooted();
        let state = roster.state().unwrap();
        let phone = members.get(1).unwrap().device_id();
        let prefix = tunnel::Prefix::from_parameter(&state.params.ula).unwrap();
        let ipv4 = tunnel::Ipv4Holdings::of_state(&state).of(&phone).unwrap();
        for query in [
            Query::Name("PHONE".into()),
            Query::Ipv6(tunnel::address_of(&phone, &prefix)),
            Query::Ipv4(ipv4),
        ] {
            assert_eq!(resolve(&state, &query), Some(phone), "{query:?}");
            let mut light = light_for(&roster, &members.first().unwrap().device_id());
            let evidence = roster.evidence_for(&phone).unwrap().to_bytes();
            assert_eq!(take_answer(&mut light, &query, &evidence), Ok(phone));
            assert!(light.state().devices.contains_key(&phone), "and learns it");
        }
    }

    #[test]
    fn a_false_answer_is_refused_and_the_peer_stays_unknown() {
        let (roster, members) = rooted();
        let phone = members.get(1).unwrap().device_id();
        let sensor = members.get(2).unwrap().device_id();
        let mut light = light_for(&roster, &members.first().unwrap().device_id());

        // Asked for the phone, answered with the sensor's evidence: genuine, and
        // not what was asked.
        let wrong = roster.evidence_for(&sensor).unwrap().to_bytes();
        assert_eq!(
            take_answer(&mut light, &Query::Name("phone".into()), &wrong),
            Err(Refusal::NotAsked)
        );
        assert!(!light.state().devices.contains_key(&phone));
        assert!(!light.state().devices.contains_key(&sensor), "nor is the other learned");

        // And nothing known is said as such.
        assert_eq!(
            take_answer(&mut light, &Query::Name("phone".into()), &[]),
            Err(Refusal::Unknown)
        );
    }

    #[test]
    fn roots_read_back_as_written() {
        let roots = vec![vec![1, 2, 3], Vec::new(), vec![9; 300]];
        assert_eq!(decode_roots(&encode_roots(&roots)), Some(roots));
        assert_eq!(decode_roots(&[0, 0, 0, 5, 1]), None, "a root cut short");
    }
}

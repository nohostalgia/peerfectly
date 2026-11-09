//! What a board is given over its cable, and the lines it is given in
//! (`scalable-membership` 15.4): shared by the board, the production station
//! and `peerfectly board`, so that both ends read one format.
//!
//! The lines, ASCII, one each way at a time:
//!
//! ```text
//! board    peerfectly-board 1 keys <signing> <transport> <attestation> serial <serial>
//! station  peerfectly-provision 1 <given>
//! board    peerfectly-board 1 taken <digest>
//! board    peerfectly-board 1 refused <why, in words>
//! station  peerfectly-forget 1
//! ```
//!
//! Every value is hex. The board's keys are made on the board and never cross
//! the cable; only their public halves do.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use roster::hex;

/// The version of these lines.
pub const VERSION: &str = "1";

/// The longest line a board reads: what a station gives, in hex, with room.
pub const MAX_LINE: usize = 48 * 1024;

/// How many anchors' evidence a station gives a board: as many as a member
/// keeps.
pub const ANCHORS_GIVEN: usize = crate::seeking::ANCHORS_PER_MEMBER;

/// What a station gives a board: everything public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Given {
    /// The relay's convesso address.
    pub relay_key: [u8; 32],
    /// Where the relay is reached: an address, the board resolves no name.
    pub relay: SocketAddr,
    /// The link the board reaches the network over: a WiFi network's name,
    /// empty for a board on a wire.
    pub link: String,
    /// Its passphrase.
    pub passphrase: String,
    /// The network's root, signed, that the board starts from.
    pub root: Vec<u8>,
    /// The root of the devices' tree under it.
    pub devices_root: [u8; 32],
    /// The network's parameters under it.
    pub params: Vec<u8>,
    /// The evidence of the anchors the board will turn to.
    pub anchors: Vec<Vec<u8>>,
}

/// Writes `bytes` preceded by their length.
fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Reads bytes preceded by their length, and what follows.
fn take(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (length, rest) = bytes.split_at_checked(4)?;
    let length = usize::try_from(u32::from_be_bytes(length.try_into().ok()?)).ok()?;
    rest.split_at_checked(length)
}

impl Given {
    /// Its bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.relay_key);
        match self.relay.ip() {
            IpAddr::V4(ip) => {
                out.push(4);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(6);
                out.extend_from_slice(&ip.octets());
            }
        }
        out.extend_from_slice(&self.relay.port().to_be_bytes());
        put(&mut out, self.link.as_bytes());
        put(&mut out, self.passphrase.as_bytes());
        put(&mut out, &self.root);
        out.extend_from_slice(&self.devices_root);
        put(&mut out, &self.params);
        out.extend_from_slice(&u32::try_from(self.anchors.len()).unwrap_or(u32::MAX).to_be_bytes());
        for anchor in &self.anchors {
            put(&mut out, anchor);
        }
        out
    }

    /// Read back; `None` for anything that is not one.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (relay_key, rest) = bytes.split_at_checked(32)?;
        let (&family, rest) = rest.split_first()?;
        let (ip, rest): (IpAddr, &[u8]) = match family {
            4 => {
                let (ip, rest) = rest.split_at_checked(4)?;
                (Ipv4Addr::from(<[u8; 4]>::try_from(ip).ok()?).into(), rest)
            }
            6 => {
                let (ip, rest) = rest.split_at_checked(16)?;
                (Ipv6Addr::from(<[u8; 16]>::try_from(ip).ok()?).into(), rest)
            }
            _ => return None,
        };
        let (port, rest) = rest.split_at_checked(2)?;
        let port = u16::from_be_bytes(port.try_into().ok()?);
        let (link, rest) = take(rest)?;
        let (passphrase, rest) = take(rest)?;
        let (root, rest) = take(rest)?;
        let (devices_root, rest) = rest.split_at_checked(32)?;
        let (params, rest) = take(rest)?;
        let (count, mut rest) = rest.split_at_checked(4)?;
        let count = u32::from_be_bytes(count.try_into().ok()?);
        if usize::try_from(count).ok()? > ANCHORS_GIVEN {
            return None;
        }
        let mut anchors = Vec::new();
        for _ in 0..count {
            let (anchor, after) = take(rest)?;
            anchors.push(anchor.to_vec());
            rest = after;
        }
        if !rest.is_empty() {
            return None;
        }
        Some(Self {
            relay_key: relay_key.try_into().ok()?,
            relay: SocketAddr::new(ip, port),
            link: String::from(core::str::from_utf8(link).ok()?),
            passphrase: String::from(core::str::from_utf8(passphrase).ok()?),
            root: root.to_vec(),
            devices_root: devices_root.try_into().ok()?,
            params: params.to_vec(),
            anchors,
        })
    }

    /// The digest a board answers with: what the station checks it took.
    #[must_use]
    pub fn digest(&self) -> [u8; 16] {
        let hash = blake3::hash(&self.to_bytes());
        let mut out = [0_u8; 16];
        if let Some(first) = hash.as_bytes().get(..16) {
            out.copy_from_slice(first);
        }
        out
    }
}

/// A line on the cable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// A board's public keys and serial.
    Keys {
        /// Its signing key.
        signing: [u8; 32],
        /// Its transport key.
        transport: [u8; 32],
        /// Its attestation key.
        attestation: [u8; 32],
        /// Its serial.
        serial: Vec<u8>,
    },
    /// What a station gives.
    Provision(Given),
    /// A board took it: its digest.
    Taken([u8; 16]),
    /// A board refused it, and why.
    Refused(String),
    /// A station tells a board to forget its keys and what it was given.
    Forget,
}

/// A 32-byte value in hex.
fn key(text: &str) -> Option<[u8; 32]> {
    hex::decode(text)?.try_into().ok()
}

impl Line {
    /// Reads a line; `None` for anything that is not one of these.
    #[must_use]
    pub fn parse(line: &str) -> Option<Self> {
        let mut words = line.split_ascii_whitespace();
        match (words.next()?, words.next()?) {
            ("peerfectly-board", VERSION) => match words.next()? {
                "keys" => {
                    let signing = key(words.next()?)?;
                    let transport = key(words.next()?)?;
                    let attestation = key(words.next()?)?;
                    if words.next()? != "serial" {
                        return None;
                    }
                    let serial = hex::decode(words.next()?)?;
                    Some(Self::Keys { signing, transport, attestation, serial })
                }
                "taken" => Some(Self::Taken(hex::decode(words.next()?)?.try_into().ok()?)),
                "refused" => {
                    let why: Vec<&str> = words.collect();
                    Some(Self::Refused(why.join(" ")))
                }
                _ => None,
            },
            ("peerfectly-provision", VERSION) => {
                Some(Self::Provision(Given::from_bytes(&hex::decode(words.next()?)?)?))
            }
            ("peerfectly-forget", VERSION) => Some(Self::Forget),
            _ => None,
        }
    }

    /// The line's text, without its end.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Keys { signing, transport, attestation, serial } => alloc::format!(
                "peerfectly-board {VERSION} keys {} {} {} serial {}",
                hex::encode(signing),
                hex::encode(transport),
                hex::encode(attestation),
                hex::encode(serial)
            ),
            Self::Provision(given) => {
                alloc::format!("peerfectly-provision {VERSION} {}", hex::encode(&given.to_bytes()))
            }
            Self::Taken(digest) => {
                alloc::format!("peerfectly-board {VERSION} taken {}", hex::encode(digest))
            }
            Self::Refused(why) => alloc::format!("peerfectly-board {VERSION} refused {why}"),
            Self::Forget => alloc::format!("peerfectly-forget {VERSION}"),
        }
    }
}

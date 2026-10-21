//! What a device announces about where it can be reached.
//!
//! # The device signs its own record
//!
//! Nothing in a record requires authority. Current addresses are ephemeral facts
//! a device knows about itself; DESIGN.md §4.1 keeps them out of the roster for
//! exactly that reason, because the roster holds only what an admin must decide.
//!
//! # It is signed with the **transport** key
//!
//! Not the signing key. The transport key is what a peer authenticates the
//! resulting session against, so the key that says *I am here* is the key that
//! will prove *I am me*. It also keeps the signing key out of a hot path: an
//! address changes whenever a network changes, and §2.3's signing key may live
//! behind a biometric prompt.
//!
//! # Encoding
//!
//! Roster's canonical CBOR, not a second encoder: definite lengths, minimal
//! integer widths, length-first map key ordering, every field exactly once, no
//! trailing bytes, and rejection rather than repair.

use roster::cbor::{Reader, Writer};
use roster::id::NetworkId;
use roster::sign::PublicKey;
use roster::types::Algorithm;

use crate::error::{Error, Result};
use crate::limits;

/// Field names of a record, in canonical order.
///
/// Length-first: `key`, `seq` and `net` are three bytes and compare bytewise;
/// `addrs` is five. Alphabetical order would put `addrs` first and produce bytes
/// a conforming decoder refuses.
pub const RECORD_SCHEMA: &[&str] = &["key", "net", "seq", "addrs"];

/// Where a device says it can be reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The device's transport public key. The record is verified with it.
    pub key: PublicKey,
    /// The network this record belongs to.
    pub network: NetworkId,
    /// Increases with every announcement. The only freshness rule there is.
    pub sequence: u64,
    /// Addresses the device believes it is reachable at.
    ///
    /// Opaque strings. This crate does not parse them: the transport decides
    /// what an address means.
    pub addresses: Vec<String>,
}

impl Record {
    /// Builds a record, checking every bound.
    ///
    /// # Errors
    ///
    /// When there are more addresses than [`limits::MAX_RECORD_ADDRESSES`], or
    /// one is longer than [`limits::MAX_ADDRESS_LEN`].
    pub fn new(
        key: PublicKey,
        network: NetworkId,
        sequence: u64,
        addresses: Vec<String>,
    ) -> Result<Self> {
        if addresses.len() > limits::MAX_RECORD_ADDRESSES {
            return Err(Error::Malformed(roster::Error::LimitExceeded("address count")));
        }
        if addresses.iter().any(|address| address.len() > limits::MAX_ADDRESS_LEN) {
            return Err(Error::Malformed(roster::Error::LimitExceeded("address length")));
        }
        Ok(Self { key, network, sequence, addresses })
    }

    /// Writes the canonical bytes a signature covers.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.map(4);
        writer.key("key").bytes(self.key.as_bytes());
        writer.key("net").bytes(self.network.as_bytes());
        writer.key("seq").u64(self.sequence);
        writer.key("addrs").array(self.addresses.len() as u64);
        for address in &self.addresses {
            writer.str(address);
        }
        writer.finish()
    }

    /// Reads a record, refusing anything non-canonical rather than repairing it.
    ///
    /// # Errors
    ///
    /// When the bytes are not a canonical record within every bound.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > limits::MAX_RECORD_SIZE {
            return Err(Error::Malformed(roster::Error::LimitExceeded("record size")));
        }
        let available = input.len();
        let mut reader = Reader::new(input);
        let mut map = reader.map(RECORD_SCHEMA).map_err(Error::Malformed)?;

        let key_bytes = map
            .key("key")
            .and_then(|value| value.bytes(64, "record key"))
            .map_err(Error::Malformed)?
            .to_vec();
        let key = PublicKey::new(Algorithm::Ed25519, key_bytes).map_err(Error::Malformed)?;

        let net =
            map.key("net").and_then(|value| value.fixed_bytes(32)).map_err(Error::Malformed)?;
        let mut network_bytes = [0u8; 32];
        network_bytes.copy_from_slice(net);
        let network = NetworkId::from_bytes(network_bytes);

        let sequence = map.key("seq").and_then(|value| value.u64()).map_err(Error::Malformed)?;

        let addresses = {
            let value = map.key("addrs").map_err(Error::Malformed)?;
            let declared =
                value.array(limits::MAX_RECORD_ADDRESSES, "addresses").map_err(Error::Malformed)?;
            // Every address costs at least one byte, so a count exceeding the
            // whole payload cannot be honest. Checked before reading any of
            // them, and nothing is reserved to the declared size either way.
            if declared > available {
                return Err(Error::Malformed(roster::Error::UnexpectedEof));
            }
            let mut addresses = Vec::new();
            for _ in 0..declared {
                addresses.push(
                    value
                        .str(limits::MAX_ADDRESS_LEN, "address length")
                        .map_err(Error::Malformed)?
                        .to_owned(),
                );
            }
            addresses
        };

        map.finish().map_err(Error::Malformed)?;
        reader.finish().map_err(Error::Malformed)?;
        Self::new(key, network, sequence, addresses)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn record() -> Record {
        let key = PublicKey::new(Algorithm::Ed25519, RFC_8032_KEY.to_vec()).unwrap();
        Record::new(
            key,
            NetworkId::from_bytes([9; 32]),
            1_700_000_000,
            vec!["192.168.1.5:41641".to_owned(), "[fe80::1]:41641".to_owned()],
        )
        .unwrap()
    }

    /// A record encodes to fixed bytes. An announcement is signed over them, so
    /// a change would make every device's announcements unreadable to every
    /// other.
    #[test]
    fn a_record_encodes_to_its_known_bytes() {
        assert_eq!(hex_of(&record().encode()), KNOWN_BYTES);
    }

    #[test]
    fn a_record_survives_its_own_encoding() {
        let record = record();
        assert_eq!(Record::decode(&record.encode()), Ok(record));
    }

    #[test]
    fn a_record_beyond_its_bounds_is_refused() {
        let key = PublicKey::new(Algorithm::Ed25519, RFC_8032_KEY.to_vec()).unwrap();
        let network = NetworkId::from_bytes([9; 32]);
        let many = vec!["a".to_owned(); limits::MAX_RECORD_ADDRESSES + 1];
        assert!(Record::new(key.clone(), network, 1, many).is_err());
        let long = vec!["a".repeat(limits::MAX_ADDRESS_LEN + 1)];
        assert!(Record::new(key, network, 1, long).is_err());
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The public key of RFC 8032's first test vector: a real point.
    const RFC_8032_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    /// The bytes of [`record`], fixed so that a change to the encoding is seen
    /// rather than carried silently onto the wire.
    const KNOWN_BYTES: &str = concat!(
        "a4636b65795820d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a636e6574",
        "58200909090909090909090909090909090909090909090909090909090909090909637365711a6553f100",
        "65616464727382713139322e3136382e312e353a34313634316f5b666538303a3a315d3a3431363431"
    );
}

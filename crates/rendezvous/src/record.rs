//! What a device publishes about where it can be reached.
//!
//! # The device signs its own record
//!
//! Nothing in a record requires authority. Current addresses, online state and
//! exposed ports are ephemeral facts a device knows about itself; DESIGN.md §4.1
//! keeps them out of the roster for exactly that reason, because the roster
//! holds only what an admin must decide.
//!
//! A record signed by an admin would put an authority in the path of a fact no
//! authority is needed for, and a device could not update its own address while
//! the admin was away.
//!
//! # It is signed with the **transport** key
//!
//! Not the signing key. The transport key is what a peer authenticates the
//! resulting session against, so the key that says *I am here* is the key that
//! will prove *I am me*. Signing with the other key would mean publishing an
//! address under one identity and answering under another, with the join between
//! them living only in the roster — a lookup an attacker would enjoy confusing.
//!
//! It also keeps the signing key out of a hot path: an address changes whenever
//! a network changes, and §2.3's signing key may live behind a biometric prompt.
//!
//! # Encoding
//!
//! Roster's canonical CBOR, not a second encoder: definite lengths, minimal
//! integer widths, length-first map key ordering, every field exactly once, no
//! trailing bytes, and rejection rather than repair.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use roster::cbor::{Reader, Writer};
use roster::id::NetworkId;
use roster::limits::SIGNATURE_LEN;
use roster::sign::{PublicKey, Signer};
use roster::types::Algorithm;

use crate::error::{Error, Limit, Result};
use crate::limits;

/// The version tag every record signature is bound to.
///
/// The fourth signing context in the system, after `roster/v1`,
/// `roster-snapshot/v1` and `transport-session/v1`. A record must not verify as
/// any of those, and none of those as a record — the transport key already signs
/// session challenges, and without separation a record could be presented as a
/// handshake or the reverse.
///
/// A change to the encoding is a change to this string, which invalidates every
/// existing signature by construction rather than by convention.
pub const DOMAIN_TAG: &str = "rendezvous-record/v2";

/// Field names of a record, in canonical order.
///
/// Length-first: `key`, `seq` and `net` are three bytes and compare bytewise;
/// `addrs` is five. Alphabetical order would put `addrs` first and produce bytes
/// a conforming decoder refuses.
pub const RECORD_SCHEMA: &[&str] = &["key", "net", "seq", "addrs"];

/// Where a device says it can be reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The device's transport public key. The record is stored under it and
    /// verified with it.
    pub key: PublicKey,
    /// The network this record belongs to.
    pub network: NetworkId,
    /// Increases with every publication. The only freshness rule there is.
    pub sequence: u64,
    /// Addresses the device believes it is reachable at.
    ///
    /// Opaque strings. This crate does not parse them: the transport decides
    /// what an address means, and a rendezvous that parsed them would need
    /// changing whenever the transport's addressing did.
    pub addresses: Vec<String>,
}

impl Record {
    /// Builds a record, checking every bound.
    pub fn new(
        key: PublicKey,
        network: NetworkId,
        sequence: u64,
        addresses: Vec<String>,
    ) -> Result<Self> {
        if addresses.len() > limits::MAX_ADDRESSES {
            return Err(Limit::AddressCount {
                count: addresses.len(),
                limit: limits::MAX_ADDRESSES,
            }
            .into());
        }
        if let Some(long) = addresses.iter().find(|a| a.len() > limits::MAX_ADDRESS_LEN) {
            return Err(
                Limit::RecordSize { len: long.len(), limit: limits::MAX_ADDRESS_LEN }.into()
            );
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
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > limits::MAX_RECORD_SIZE {
            return Err(
                Limit::RecordSize { len: input.len(), limit: limits::MAX_RECORD_SIZE }.into()
            );
        }
        let available = input.len();
        let mut reader = Reader::new(input);
        let mut map = reader.map(RECORD_SCHEMA)?;

        let key_bytes = map.key("key")?.bytes(64, "record key")?.to_vec();
        let key = PublicKey::new(Algorithm::Ed25519, key_bytes)?;

        let net = map.key("net")?.fixed_bytes(32)?;
        let mut network_bytes = [0u8; 32];
        network_bytes.copy_from_slice(net);
        let network = NetworkId::from_bytes(network_bytes);

        let sequence = map.key("seq")?.u64()?;

        let addresses = {
            let value = map.key("addrs")?;
            let declared =
                value.array(limits::MAX_ADDRESSES, "addresses").map_err(|reason| match reason {
                    roster::Error::LimitExceeded(_) => {
                        Error::Limit(Limit::AddressCount { count: 0, limit: limits::MAX_ADDRESSES })
                    }
                    other => Error::Malformed(other),
                })?;
            // Every address costs at least one byte, so a count exceeding the
            // whole payload cannot be honest. Checked before reading any of
            // them, and nothing is reserved to the declared size either way.
            if declared > available {
                return Err(Error::Malformed(roster::Error::UnexpectedEof));
            }
            let mut addresses = Vec::new();
            for _ in 0..declared {
                addresses.push(value.str(limits::MAX_ADDRESS_LEN, "address length")?.to_owned());
            }
            addresses
        };

        map.finish()?;
        reader.finish()?;
        Self::new(key, network, sequence, addresses)
    }
}

/// Field names of a record as it travels, in canonical order.
///
/// `key` and `seq` are three bytes and compare bytewise; `sealed` is six. The
/// network and the addresses are not here: they are inside `sealed`.
pub const WIRE_SCHEMA: &[&str] = &["key", "seq", "sealed"];

/// Field names of what the seal hides, in canonical order.
pub const SEALED_SCHEMA: &[&str] = &["net", "addrs"];

/// The context the sealing key is derived under.
///
/// **Not local discovery's.** One network's announcement key must never open
/// its rendezvous records, nor the reverse.
pub const SEAL_CONTEXT: &str = "peerfectly rendezvous seal v1";

/// A nonce's length.
pub const NONCE_LEN: usize = 12;

/// Builds the byte string a record signature covers.
///
/// **Without the network's id**, so the service verifies a record without
/// knowing which network it belongs to — the one thing it must not learn. The
/// sealed contents are inside `wire_bytes`, so the signature covers them: an
/// altered ciphertext fails here, before anything tries to open it.
///
/// Framed exactly as roster's envelopes are: each variable-length component
/// preceded by its length as a big-endian `u16`, so no two component tuples can
/// concatenate to the same bytes.
#[must_use]
pub fn signing_input(wire_bytes: &[u8]) -> Vec<u8> {
    let tag = DOMAIN_TAG.as_bytes();
    let mut out = Vec::with_capacity(tag.len().saturating_add(wire_bytes.len()).saturating_add(4));
    push_framed(&mut out, tag);
    push_framed(&mut out, wire_bytes);
    out
}

/// Appends a component preceded by its big-endian `u16` length.
fn push_framed(out: &mut Vec<u8>, component: &[u8]) {
    let len = u16::try_from(component.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(component);
}

/// The key a network's records are sealed under.
///
/// Derived from a value that is not secret — every member knows the network's
/// id, and so does every revoked ex-member — which is the whole limit of this
/// protection. It keeps the network and the addresses from the service's
/// operator and from anyone who never held the roster, and from nobody else.
fn seal_key(network: &NetworkId) -> Key {
    Key::from(blake3::derive_key(SEAL_CONTEXT, network.as_bytes()))
}

/// The canonical bytes of what the seal hides.
fn encode_sealed(record: &Record) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.map(2);
    writer.key("net").bytes(record.network.as_bytes());
    writer.key("addrs").array(record.addresses.len() as u64);
    for address in &record.addresses {
        writer.str(address);
    }
    writer.finish()
}

/// Reads what the seal hid, as strictly as a record.
fn decode_sealed(input: &[u8]) -> Result<(NetworkId, Vec<String>)> {
    let available = input.len();
    let mut reader = Reader::new(input);
    let mut map = reader.map(SEALED_SCHEMA)?;

    let net = map.key("net")?.fixed_bytes(32)?;
    let mut network_bytes = [0u8; 32];
    network_bytes.copy_from_slice(net);

    let value = map.key("addrs")?;
    let declared =
        value.array(limits::MAX_ADDRESSES, "addresses").map_err(|reason| match reason {
            roster::Error::LimitExceeded(_) => {
                Error::Limit(Limit::AddressCount { count: 0, limit: limits::MAX_ADDRESSES })
            }
            other => Error::Malformed(other),
        })?;
    if declared > available {
        return Err(Error::Malformed(roster::Error::UnexpectedEof));
    }
    let mut addresses = Vec::new();
    for _ in 0..declared {
        addresses.push(value.str(limits::MAX_ADDRESS_LEN, "address length")?.to_owned());
    }

    map.finish()?;
    reader.finish()?;
    Ok((NetworkId::from_bytes(network_bytes), addresses))
}

/// The canonical bytes of a record as it travels.
fn encode_wire(key: &PublicKey, sequence: u64, sealed: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.map(3);
    writer.key("key").bytes(key.as_bytes());
    writer.key("seq").u64(sequence);
    writer.key("sealed").bytes(sealed);
    writer.finish()
}

/// A record as it travels: signed in the clear, sealed inside.
///
/// What anyone holding one can read is the device's transport key — a
/// pseudonym, since every device has a separate identity per network — the
/// sequence number, and the size of the sealed contents. The network and the
/// addresses need [`Self::open`] and the network's id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRecord {
    /// The exact bytes that were signed. Kept rather than re-encoded, so
    /// verification is over what arrived.
    bytes: Vec<u8>,
    /// The device's transport key: what the record is stored and verified under.
    key: PublicKey,
    /// Increases with every publication.
    sequence: u64,
    /// Nonce and ciphertext.
    sealed: Vec<u8>,
    /// The signature over [`signing_input`] of `bytes`.
    signature: [u8; SIGNATURE_LEN],
}

impl SignedRecord {
    /// Seals and signs a record, with a fresh random nonce.
    ///
    /// # Errors
    ///
    /// When no randomness is available, or signing fails.
    pub fn sign(record: Record, signer: &dyn Signer) -> Result<Self> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| Error::SignatureInvalid)?;
        Self::sign_with_nonce(&record, signer, nonce)
    }

    /// [`Self::sign`] with the nonce supplied, so vectors are reproducible.
    ///
    /// # Errors
    ///
    /// When sealing or signing fails.
    pub fn sign_with_nonce(
        record: &Record,
        signer: &dyn Signer,
        nonce: [u8; NONCE_LEN],
    ) -> Result<Self> {
        let cipher = ChaCha20Poly1305::new(&seal_key(&record.network));
        let ciphertext = cipher
            .encrypt(&Nonce::from(nonce), encode_sealed(record).as_slice())
            .map_err(|_| Limit::RecordSize { len: 0, limit: limits::MAX_RECORD_SIZE })?;
        let mut sealed = Vec::with_capacity(NONCE_LEN.saturating_add(ciphertext.len()));
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);

        let bytes = encode_wire(&record.key, record.sequence, &sealed);
        let raw = signer.sign(&signing_input(&bytes))?;
        let signature: [u8; SIGNATURE_LEN] = raw.try_into().map_err(|_| Error::SignatureInvalid)?;
        Ok(Self { bytes, key: record.key.clone(), sequence: record.sequence, sealed, signature })
    }

    /// Reads and verifies a record from the wire, without opening it.
    ///
    /// This is all the service does, and all it can: it verifies the device's
    /// signature and never learns the network. Verification is over the bytes
    /// as received, never a re-encoding of the decoded value.
    ///
    /// # Errors
    ///
    /// When the record is too large, non-canonical, or does not verify.
    pub fn decode_and_verify(input: &[u8]) -> Result<Self> {
        let bound = limits::MAX_WIRE_SIZE.saturating_add(SIGNATURE_LEN);
        if input.len() > bound {
            return Err(Limit::RecordSize { len: input.len(), limit: bound }.into());
        }
        let split = input.len().checked_sub(SIGNATURE_LEN).ok_or(Error::SignatureInvalid)?;
        let (body, tail) = input.split_at(split);
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(tail);

        let mut reader = Reader::new(body);
        let mut map = reader.map(WIRE_SCHEMA)?;
        let key_bytes = map.key("key")?.bytes(64, "record key")?.to_vec();
        let key = PublicKey::new(Algorithm::Ed25519, key_bytes)?;
        let sequence = map.key("seq")?.u64()?;
        let sealed = map
            .key("sealed")?
            .bytes(limits::MAX_RECORD_SIZE.saturating_add(limits::SEAL_OVERHEAD), "sealed")?
            .to_vec();
        map.finish()?;
        reader.finish()?;
        if sealed.len() < limits::SEAL_OVERHEAD {
            return Err(Error::Malformed(roster::Error::UnexpectedEof));
        }

        key.verify(&signing_input(body), &signature).map_err(|_| Error::SignatureInvalid)?;
        Ok(Self { bytes: body.to_vec(), key, sequence, sealed, signature })
    }

    /// Opens the record, for a device that knows `network`.
    ///
    /// Opening is never evidence of who published: the signature, already
    /// verified, is that. A record that does not open, or that names another
    /// network inside, is refused and no address is returned.
    ///
    /// # Errors
    ///
    /// [`Error::ForeignNetwork`] when it was not sealed for `network`; a decoding
    /// error when what was sealed is not a record's contents.
    pub fn open(&self, network: &NetworkId) -> Result<Record> {
        let (nonce, ciphertext) = self.sealed.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::ForeignNetwork)?;
        let cipher = ChaCha20Poly1305::new(&seal_key(network));
        let plain =
            cipher.decrypt(&Nonce::from(nonce), ciphertext).map_err(|_| Error::ForeignNetwork)?;
        let (sealed_for, addresses) = decode_sealed(&plain)?;
        if sealed_for != *network {
            return Err(Error::ForeignNetwork);
        }
        Record::new(self.key.clone(), sealed_for, self.sequence, addresses)
    }

    /// The device's transport key, which the record is stored under.
    #[must_use]
    pub const fn key(&self) -> &PublicKey {
        &self.key
    }

    /// The sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The exact bytes that were signed.
    #[must_use]
    pub fn signed_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }

    /// The record and its signature, as they travel.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.bytes.clone();
        out.extend_from_slice(&self.signature);
        out
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test reports a failed expectation by panicking")]
mod tests {
    use roster::cbor::is_canonical_schema;

    use super::*;

    /// Length-first, not alphabetical. This is the single easiest rule for a
    /// second implementation to get wrong, because it disagrees with the order a
    /// programmer reaches for by habit.
    #[test]
    fn the_schema_is_in_canonical_key_order() {
        assert!(is_canonical_schema(RECORD_SCHEMA), "{RECORD_SCHEMA:?}");
        assert_eq!(RECORD_SCHEMA, &["key", "net", "seq", "addrs"]);
    }

    /// The tag is distinct from every other signing context in the system. A
    /// record that verified as a session handshake, or the reverse, would be a
    /// cross-protocol confusion.
    #[test]
    fn the_tag_is_distinct_from_every_other_context() {
        for other in ["roster/v1", "roster-snapshot/v1", "transport-session/v1"] {
            assert_ne!(DOMAIN_TAG, other);
        }
        assert_eq!(
            DOMAIN_TAG, "rendezvous-record/v2",
            "v1 is withdrawn: a v1 record never verifies as v2"
        );
    }

    #[test]
    fn the_signing_input_carries_its_own_tag() {
        let input = signing_input(b"body");
        assert!(
            input.windows(DOMAIN_TAG.len()).any(|w| w == DOMAIN_TAG.as_bytes()),
            "the tag must be inside what is signed"
        );
    }

    /// Components are length-framed, so no two different tuples concatenate to
    /// the same bytes.
    #[test]
    fn framing_keeps_components_apart() {
        assert_ne!(signing_input(b"ab"), signing_input(b"a"));
    }

    #[test]
    fn the_wire_schemas_are_in_canonical_key_order() {
        assert!(is_canonical_schema(WIRE_SCHEMA), "{WIRE_SCHEMA:?}");
        assert!(is_canonical_schema(SEALED_SCHEMA), "{SEALED_SCHEMA:?}");
    }

    /// A real key: `PublicKey::new` validates the point, so an arbitrary 32
    /// bytes is not one.
    fn a_key() -> PublicKey {
        identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates").public_key()
    }

    #[test]
    fn too_many_addresses_are_refused() {
        let key = a_key();
        let many = vec!["a".to_owned(); limits::MAX_ADDRESSES + 1];
        match Record::new(key, NetworkId::from_bytes([0; 32]), 1, many) {
            Err(Error::Limit(Limit::AddressCount { count, limit })) => {
                assert_eq!(count, limits::MAX_ADDRESSES + 1);
                assert_eq!(limit, limits::MAX_ADDRESSES);
            }
            other => panic!("expected a bound refusal naming the count, got {other:?}"),
        }
    }

    #[test]
    fn an_over_long_address_is_refused() {
        let key = a_key();
        let long = vec!["h".repeat(limits::MAX_ADDRESS_LEN + 1)];
        assert!(Record::new(key, NetworkId::from_bytes([0; 32]), 1, long).is_err());
    }

    /// Hand-built bytes, because an encoder cannot be trusted to produce the
    /// inputs that prove it rejects things. The same discipline roster's
    /// negative vectors use.
    fn params(build: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut writer = Writer::new();
        build(&mut writer);
        writer.finish()
    }

    /// A valid record's field values, for building near-misses around.
    fn parts() -> (Vec<u8>, [u8; 32]) {
        let key = a_key();
        (key.as_bytes().to_vec(), [9u8; 32])
    }

    #[test]
    fn a_canonical_record_round_trips_exactly() {
        let key = a_key();
        let record = Record::new(
            key,
            NetworkId::from_bytes([9; 32]),
            3,
            vec!["ip:a".to_owned(), "ip:b".to_owned()],
        )
        .expect("within bounds");

        let encoded = record.encode();
        let decoded = Record::decode(&encoded).expect("decodes");
        assert_eq!(decoded, record);
        assert_eq!(decoded.encode(), encoded, "re-encoding reproduces the bytes");
    }

    #[test]
    fn misordered_keys_are_refused() {
        let (key, net) = parts();
        let bytes = params(|w| {
            w.map(4);
            // Alphabetical rather than length-first: `addrs` before `key`.
            w.key("addrs").array(0);
            w.key("key").bytes(&key);
            w.key("net").bytes(&net);
            w.key("seq").u64(1);
        });
        assert!(matches!(
            Record::decode(&bytes),
            Err(Error::Malformed(roster::Error::KeyOrdering | roster::Error::UnknownField))
        ));
    }

    #[test]
    fn a_repeated_key_is_refused() {
        let (key, net) = parts();
        // The entry count still matches the schema, so this reaches the key
        // comparison rather than being refused on the count alone.
        let bytes = params(|w| {
            w.map(4);
            w.key("key").bytes(&key);
            w.key("key").bytes(&key);
            w.key("net").bytes(&net);
            w.key("seq").u64(1);
        });
        assert!(matches!(
            Record::decode(&bytes),
            Err(Error::Malformed(roster::Error::DuplicateKey))
        ));
    }

    #[test]
    fn a_missing_field_is_refused() {
        let (key, net) = parts();
        let bytes = params(|w| {
            w.map(3);
            w.key("key").bytes(&key);
            w.key("net").bytes(&net);
            w.key("seq").u64(1);
        });
        assert!(matches!(
            Record::decode(&bytes),
            Err(Error::Malformed(roster::Error::MissingField))
        ));
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let key = a_key();
        let record =
            Record::new(key, NetworkId::from_bytes([9; 32]), 1, Vec::new()).expect("within bounds");
        let mut bytes = record.encode();
        bytes.push(0);
        assert!(matches!(
            Record::decode(&bytes),
            Err(Error::Malformed(roster::Error::TrailingData))
        ));
    }

    /// A signature must not verify over a re-encoding of what this
    /// implementation understood, only over what the signer actually signed.
    #[test]
    fn verification_is_over_the_received_bytes() {
        let device = identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let record = Record::new(
            device.public_key(),
            NetworkId::from_bytes([9; 32]),
            1,
            vec!["ip:a".to_owned()],
        )
        .expect("within bounds");
        let signed = SignedRecord::sign(record, device.signer()).expect("signs");

        let wire = signed.to_bytes();
        let recovered = SignedRecord::decode_and_verify(&wire).expect("verifies");
        assert_eq!(recovered.signed_bytes(), signed.signed_bytes());

        // One byte different inside the body and it no longer verifies.
        let mut tampered = wire;
        if let Some(byte) = tampered.first_mut() {
            *byte ^= 0x01;
        }
        assert!(SignedRecord::decode_and_verify(&tampered).is_err());
    }

    fn sealed_record(
        device: &identity::PrivateKey,
        network: [u8; 32],
        addresses: &[&str],
    ) -> SignedRecord {
        let record = Record::new(
            device.public_key(),
            NetworkId::from_bytes(network),
            7,
            addresses.iter().map(|a| (*a).to_owned()).collect(),
        )
        .expect("within bounds");
        SignedRecord::sign(record, device.signer()).expect("signs")
    }

    /// **What the service holds names neither the network nor an address.**
    #[test]
    fn the_network_and_the_addresses_are_not_in_the_clear() {
        let device = identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let signed = sealed_record(&device, [9; 32], &["ip:203.0.113.7:4433"]);
        let wire = signed.to_bytes();
        assert!(!wire.windows(32).any(|w| w == [9u8; 32]), "no network id");
        assert!(!wire.windows(11).any(|w| w == b"203.0.113.7"), "no address");
    }

    /// Two devices of one network, same addresses: nothing in the clear links them.
    #[test]
    fn two_records_of_one_network_share_no_sealed_bytes() {
        let one = identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let two = identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let first = sealed_record(&one, [9; 32], &["ip:203.0.113.7:4433"]);
        let second = sealed_record(&two, [9; 32], &["ip:203.0.113.7:4433"]);
        assert_ne!(first.key(), second.key());
        assert!(
            !first.sealed.windows(8).any(|w| second.sealed.windows(8).any(|v| v == w)),
            "the sealed contents share no eight bytes"
        );
    }

    /// It opens for its own network, and for no other.
    #[test]
    fn a_record_opens_for_its_network_only() {
        let device = identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let signed = sealed_record(&device, [9; 32], &["ip:203.0.113.7:4433"]);
        let wire =
            SignedRecord::decode_and_verify(&signed.to_bytes()).expect("the service verifies");

        let opened = wire.open(&NetworkId::from_bytes([9; 32])).expect("opens");
        assert_eq!(opened.addresses, vec!["ip:203.0.113.7:4433".to_owned()]);
        assert_eq!(opened.sequence, 7);
        assert!(matches!(wire.open(&NetworkId::from_bytes([8; 32])), Err(Error::ForeignNetwork)));
    }

    /// One byte of ciphertext changed, and the signature refuses the record
    /// before anything tries to open it.
    #[test]
    fn an_altered_seal_fails_the_signature() {
        let device = identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let signed = sealed_record(&device, [9; 32], &["ip:203.0.113.7:4433"]);
        let mut wire = signed.to_bytes();
        let at = wire.len().saturating_sub(SIGNATURE_LEN).saturating_sub(3);
        if let Some(byte) = wire.get_mut(at) {
            *byte ^= 0x01;
        }
        assert!(matches!(SignedRecord::decode_and_verify(&wire), Err(Error::SignatureInvalid)));
    }

    /// A record signed with a key other than the one it carries is refused, and
    /// distinguishably from a malformed one.
    #[test]
    fn a_record_signed_by_another_key_is_refused() {
        let device = identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let other = identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let record = Record::new(device.public_key(), NetworkId::from_bytes([9; 32]), 1, vec![])
            .expect("within bounds");
        let signed = SignedRecord::sign(record, other.signer()).expect("signs");
        assert!(matches!(
            SignedRecord::decode_and_verify(&signed.to_bytes()),
            Err(Error::SignatureInvalid)
        ));
    }

    /// A wire record signed as it would be, around hand-built outer bytes.
    fn wire_signed(device: &identity::PrivateKey, body: &[u8]) -> Vec<u8> {
        let mut out = body.to_vec();
        out.extend_from_slice(&device.signer().sign(&signing_input(body)).expect("signs"));
        out
    }

    /// The outer record is as strict as the inner: misordered or missing keys
    /// are refused even when the signature over them is good.
    #[test]
    fn a_non_canonical_wire_record_is_refused() {
        let device = identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let key = device.public_key().as_bytes().to_vec();
        let sealed = vec![0u8; limits::SEAL_OVERHEAD];
        let misordered = params(|w| {
            w.map(3);
            w.key("seq").u64(1);
            w.key("key").bytes(&key);
            w.key("sealed").bytes(&sealed);
        });
        let missing = params(|w| {
            w.map(2);
            w.key("key").bytes(&key);
            w.key("seq").u64(1);
        });
        for body in [misordered, missing] {
            assert!(matches!(
                SignedRecord::decode_and_verify(&wire_signed(&device, &body)),
                Err(Error::Malformed(_))
            ));
        }
    }

    /// A seal too short to hold a nonce and a tag is not a seal.
    #[test]
    fn a_truncated_seal_is_refused() {
        let device = identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let body = encode_wire(&device.public_key(), 1, &[0u8; 10]);
        assert!(matches!(
            SignedRecord::decode_and_verify(&wire_signed(&device, &body)),
            Err(Error::Malformed(_))
        ));
    }

    /// v1 is withdrawn: a record in the old shape, signed the old way, is
    /// refused rather than read.
    #[test]
    fn a_v1_record_is_refused() {
        let device = identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let record = Record::new(device.public_key(), NetworkId::from_bytes([9; 32]), 1, vec![])
            .expect("within bounds");
        let body = record.encode();
        let mut old_input = Vec::new();
        push_framed(&mut old_input, b"rendezvous-record/v1");
        push_framed(&mut old_input, record.network.as_bytes());
        push_framed(&mut old_input, &body);
        let mut wire = body;
        wire.extend_from_slice(&device.signer().sign(&old_input).expect("signs"));
        assert!(SignedRecord::decode_and_verify(&wire).is_err());
    }

    /// Sealed under this network's key and naming another inside: refused. It
    /// cannot happen by accident — a device's key is its network's — which is
    /// exactly why it is checked rather than assumed.
    #[test]
    fn a_record_naming_another_network_inside_is_refused() {
        let device = identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let ours = NetworkId::from_bytes([9; 32]);
        let theirs = Record::new(device.public_key(), NetworkId::from_bytes([8; 32]), 1, vec![])
            .expect("within bounds");

        let nonce = [5u8; NONCE_LEN];
        let cipher = ChaCha20Poly1305::new(&seal_key(&ours));
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(
            &cipher.encrypt(&Nonce::from(nonce), encode_sealed(&theirs).as_slice()).expect("seals"),
        );
        let body = encode_wire(&device.public_key(), 1, &sealed);
        let wire = SignedRecord::decode_and_verify(&wire_signed(&device, &body)).expect("verifies");
        assert!(matches!(wire.open(&ours), Err(Error::ForeignNetwork)));
    }

    /// Each network seals under its own key: another network's key fails at the
    /// cipher, before any check of what is inside. Without this, the inside
    /// check alone would be what kept networks apart.
    #[test]
    fn another_networks_key_does_not_open_the_seal() {
        let device = identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let signed = sealed_record(&device, [9; 32], &["ip:203.0.113.7:4433"]);
        let (nonce, ciphertext) = signed.sealed.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("a nonce");
        let theirs = ChaCha20Poly1305::new(&seal_key(&NetworkId::from_bytes([8; 32])));
        assert!(theirs.decrypt(&Nonce::from(nonce), ciphertext).is_err());
    }
}

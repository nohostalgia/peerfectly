//! Attestations: an admin's signed word that, at this moment, it knew these
//! heads.
//!
//! # What it deliberately cannot say
//!
//! An attestation carries the network, the heads, a sequence number and the id
//! of the key that signed — and **no roster state**. That absence is the whole
//! of its security argument, and it is structural rather than procedural:
//!
//! - it cannot be **adopted**, because there is no state in it to adopt;
//! - it cannot found or alter a network, because it is not an operation, has no
//!   place in the DAG and takes no part in merge;
//! - a device holding no roster learns nothing from one, because it names heads
//!   and a device with no graph holds no heads.
//!
//! So a stolen attestation key can declare a roster fresh and can do nothing
//! else — not because a rule refuses the rest, but because the rest cannot be
//! expressed. A [`crate::snapshot::Snapshot`] carries state, which is why it is
//! still signed by the key a person has to be present for.
//!
//! # Why it is a separate key
//!
//! The one this signs with, [`crate::types::KeyPurpose::Attestation`], is the
//! key a device may use with nobody present. On a phone every signature raises a
//! lock prompt, so an admin phone could only date its roster while somebody was
//! holding it, and a network whose only admin was a phone went stale whenever
//! that person stopped opening the app. A key that both dated a roster unattended
//! and signed operations would hand the unattended property to the signing power.
//!
//! # What it commits to
//!
//! ```text
//! Attestation = { "seq": uint, "heads": [ bstr(32) ... ],
//!                 "author": bstr(32), "network": bstr(32) }
//! ```
//!
//! No `state`, and no `depths` — depths exist in a snapshot because a node that
//! compacted has to resolve last-writer-wins without the history, and an
//! attestation resolves nothing.
//!
//! # A separate signing tag
//!
//! Attestations sign under [`ATTESTATION_DOMAIN_TAG`], never the operation or
//! snapshot tag. Three tags make confusion structurally impossible in every
//! direction rather than nearly impossible in most.

use crate::cbor::{Reader, Writer};
use crate::error::{Error, Result};
use crate::id::{KeyId, NetworkId, OperationId};
use crate::limits;
use crate::sign::{PublicKey, Signer};

/// The domain-separation tag every attestation signature carries.
///
/// Distinct from the operation and snapshot tags so that no kind of signature
/// can be made to verify as another.
pub const ATTESTATION_DOMAIN_TAG: &str = "roster-attestation/v1";

/// The field names of an attestation body, in canonical order.
const ATTESTATION_SCHEMA: &[&str] = &["seq", "heads", "author", "network"];

/// The field names of a signed attestation.
const SIGNED_ATTESTATION_SCHEMA: &[&str] = &["sig", "body"];

/// Builds the byte string an attestation signature covers.
///
/// Framed exactly as the operation and snapshot envelopes are: each
/// variable-length component preceded by its length as a big-endian `u16`, so no
/// two component tuples can concatenate to the same bytes.
#[must_use]
pub fn attestation_signing_input(network: &NetworkId, body_bytes: &[u8]) -> Vec<u8> {
    let tag = ATTESTATION_DOMAIN_TAG.as_bytes();
    let mut out = Vec::with_capacity(
        tag.len().saturating_add(limits::ID_LEN).saturating_add(body_bytes.len()).saturating_add(6),
    );
    push_framed(&mut out, tag);
    push_framed(&mut out, network.as_bytes());
    push_framed(&mut out, body_bytes);
    out
}

/// Appends a component preceded by its big-endian `u16` length.
fn push_framed(out: &mut Vec<u8>, component: &[u8]) {
    let len = u16::try_from(component.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(component);
}

/// The body of an attestation: what is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// Monotone sequence number, so a replayed older attestation cannot make a
    /// roster look fresher than the node's own reading already says.
    pub seq: u64,
    /// The id of the attestation key that signed this.
    pub author: KeyId,
    /// The heads its author held. A receiver counts this towards freshness only
    /// where it holds them itself — otherwise it has learned that it is behind,
    /// not that it is current.
    pub heads: Vec<OperationId>,
    /// The network this attestation belongs to.
    pub network: NetworkId,
}

impl Attestation {
    /// Builds an attestation body, checking its bounds.
    ///
    /// # Errors
    ///
    /// When it names no heads, or more than the limit allows.
    pub fn new(
        seq: u64,
        heads: Vec<OperationId>,
        author: KeyId,
        network: NetworkId,
    ) -> Result<Self> {
        if heads.is_empty() {
            // An attestation covering nothing dates nothing.
            return Err(Error::MissingField);
        }
        if heads.len() > limits::MAX_SNAPSHOT_HEADS {
            return Err(Error::LimitExceeded("attestation heads"));
        }
        Ok(Self { seq, author, heads, network })
    }

    /// The canonical bytes of this body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.map(4);
        writer.key("seq").u64(self.seq);
        writer.key("heads").array(self.heads.len() as u64);
        for head in &self.heads {
            writer.bytes(head.as_bytes());
        }
        writer.key("author").bytes(self.author.as_bytes());
        writer.key("network").bytes(self.network.as_bytes());
        writer.finish()
    }

    /// Reads a body from its canonical bytes.
    pub(crate) fn decode(body_bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(body_bytes);
        let mut map = reader.map(ATTESTATION_SCHEMA)?;
        let seq = map.key("seq")?.u64()?;

        let heads_reader = map.key("heads")?;
        let head_count = heads_reader.array(limits::MAX_SNAPSHOT_HEADS, "attestation heads")?;
        let mut heads = Vec::with_capacity(head_count);
        for _ in 0..head_count {
            heads.push(OperationId::decode(heads_reader)?);
        }

        let author = KeyId::decode(map.key("author")?)?;
        let network = NetworkId::decode(map.key("network")?)?;
        map.finish()?;
        reader.finish()?;

        Self::new(seq, heads, author, network)
    }
}

/// A decoded attestation whose signature has not been checked.
///
/// Holds the received body bytes, not a re-encoding: verification runs over
/// exactly what arrived, for the same reason it does for operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAttestation {
    /// The signature bytes.
    signature: [u8; limits::SIGNATURE_LEN],
    /// The exact received bytes of the signed body.
    body_bytes: Vec<u8>,
    /// The decoded body.
    body: Attestation,
}

impl RawAttestation {
    /// Decodes an attestation.
    ///
    /// # Errors
    ///
    /// When the bytes are not a canonical signed attestation.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > limits::MAX_ATTESTATION_SIZE {
            return Err(Error::LimitExceeded("attestation size"));
        }
        let mut reader = Reader::new(input);
        let mut map = reader.map(SIGNED_ATTESTATION_SCHEMA)?;
        let signature_bytes = map.key("sig")?.fixed_bytes(limits::SIGNATURE_LEN)?;
        let body_bytes =
            map.key("body")?.bytes(limits::MAX_ATTESTATION_SIZE, "attestation size")?.to_vec();
        map.finish()?;
        reader.finish()?;

        let mut signature = [0u8; limits::SIGNATURE_LEN];
        signature.copy_from_slice(signature_bytes);
        let body = Attestation::decode(&body_bytes)?;
        Ok(Self { signature, body_bytes, body })
    }

    /// The decoded body, before its signature has been checked.
    #[must_use]
    pub const fn body(&self) -> &Attestation {
        &self.body
    }

    /// Verifies the signature against a key, over the bytes that arrived.
    ///
    /// # Errors
    ///
    /// When the key is not the one the body names, or the signature does not
    /// verify.
    pub fn verify(&self, key: &PublicKey) -> Result<SignedAttestation> {
        if key.key_id() != self.body.author {
            return Err(Error::AuthorKeyMismatch);
        }
        let input = attestation_signing_input(&self.body.network, &self.body_bytes);
        key.verify(&input, &self.signature)?;
        Ok(SignedAttestation { signer: key.key_id(), body: self.body.clone() })
    }
}

/// An attestation whose signature verified against the key it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAttestation {
    /// The key whose signature was checked.
    signer: KeyId,
    /// The body.
    body: Attestation,
}

impl SignedAttestation {
    /// The key that signed it.
    #[must_use]
    pub const fn signer(&self) -> KeyId {
        self.signer
    }

    /// The body.
    #[must_use]
    pub const fn body(&self) -> &Attestation {
        &self.body
    }
}

/// Encodes a signature and body into the signed form.
fn encode_signed(signature: &[u8; limits::SIGNATURE_LEN], body_bytes: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.map(2);
    writer.key("sig").bytes(signature);
    writer.key("body").bytes(body_bytes);
    writer.finish()
}

/// Signs an attestation body, producing the bytes a peer receives.
///
/// # Errors
///
/// When signing fails, or the signature is not of the fixed width.
pub fn sign_attestation(body: &Attestation, signer: &dyn Signer) -> Result<Vec<u8>> {
    if signer.key_id() != body.author {
        // Signing under a key the body does not name would produce an
        // attestation that could never verify.
        return Err(Error::AuthorKeyMismatch);
    }
    let body_bytes = body.encode();
    if body_bytes.len() > limits::MAX_ATTESTATION_SIZE {
        return Err(Error::LimitExceeded("attestation size"));
    }
    let input = attestation_signing_input(&body.network, &body_bytes);
    let signature_bytes = signer.sign(&input)?;
    let signature: [u8; limits::SIGNATURE_LEN] =
        signature_bytes.as_slice().try_into().map_err(|_| Error::SignatureEncoding)?;
    Ok(encode_signed(&signature, &body_bytes))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;
    use crate::sign::Ed25519Signer;

    fn signer(seed: u8) -> Ed25519Signer {
        Ed25519Signer::from_seed([seed; 32])
    }

    fn network() -> NetworkId {
        NetworkId::from_bytes([9; 32])
    }

    fn head(tag: u8) -> OperationId {
        OperationId::from_bytes([tag; 32])
    }

    fn body(seq: u64, signer: &Ed25519Signer) -> Attestation {
        Attestation::new(seq, vec![head(1), head(2)], signer.key_id(), network()).expect("bounded")
    }

    #[test]
    fn a_body_round_trips() {
        let key = signer(1);
        let original = body(7, &key);
        let decoded = Attestation::decode(&original.encode()).expect("decodes");
        assert_eq!(decoded, original);
    }

    /// The absence is the requirement, so it is what the test checks. A field
    /// added here would be a field a stolen attestation key could fill.
    #[test]
    fn an_attestation_carries_no_state() {
        let key = signer(2);
        let encoded = body(1, &key).encode();
        let text = String::from_utf8_lossy(&encoded);
        assert!(!text.contains("state"), "an attestation must carry no roster state");
        assert!(!text.contains("depths"), "and nothing that resolves an ordering");
        assert_eq!(ATTESTATION_SCHEMA, &["seq", "heads", "author", "network"]);
    }

    #[test]
    fn an_attestation_with_no_heads_is_refused() {
        let key = signer(3);
        assert_eq!(
            Attestation::new(1, vec![], key.key_id(), network()).map(|_| ()),
            Err(Error::MissingField)
        );
    }

    #[test]
    fn a_signed_attestation_verifies_against_its_key() {
        let key = signer(4);
        let bytes = sign_attestation(&body(2, &key), &key).expect("signs");
        let raw = RawAttestation::decode(&bytes).expect("decodes");
        let signed = raw.verify(&key.public_key()).expect("verifies");
        assert_eq!(signed.signer(), key.key_id());
        assert_eq!(signed.body().seq, 2);
    }

    #[test]
    fn a_key_the_body_does_not_name_is_a_mismatch_not_a_failure() {
        let key = signer(5);
        let other = signer(6);
        let bytes = sign_attestation(&body(1, &key), &key).expect("signs");
        let raw = RawAttestation::decode(&bytes).expect("decodes");
        assert_eq!(raw.verify(&other.public_key()).map(|_| ()), Err(Error::AuthorKeyMismatch));
    }

    #[test]
    fn a_corrupted_signature_fails_verification() {
        let key = signer(7);
        let mut bytes = sign_attestation(&body(1, &key), &key).expect("signs");
        // The signature is the first field; flipping a byte inside it is enough.
        if let Some(slot) = bytes.get_mut(8) {
            *slot ^= 0x01;
        }
        let raw = RawAttestation::decode(&bytes).expect("still decodes");
        assert_eq!(raw.verify(&key.public_key()).map(|_| ()), Err(Error::SignatureInvalid));
    }

    /// Three tags, and no pair of them equal: a signature made for one kind must
    /// not verify as another, in any direction.
    #[test]
    fn the_three_domain_tags_are_distinct() {
        assert_ne!(ATTESTATION_DOMAIN_TAG, crate::sign::DOMAIN_TAG);
        assert_ne!(ATTESTATION_DOMAIN_TAG, crate::snapshot::SNAPSHOT_DOMAIN_TAG);
        assert_ne!(crate::snapshot::SNAPSHOT_DOMAIN_TAG, crate::sign::DOMAIN_TAG);
    }

    /// And the tags are not merely different strings: the same body bytes under
    /// two tags produce signatures neither of which verifies as the other.
    #[test]
    fn a_snapshot_signature_does_not_transfer_to_an_attestation() {
        let key = signer(8);
        let attestation = body(1, &key);
        let body_bytes = attestation.encode();

        // A signature made over the snapshot envelope, carrying these bytes.
        let wrong: [u8; limits::SIGNATURE_LEN] = key
            .sign(&crate::snapshot::snapshot_signing_input(&network(), &body_bytes))
            .expect("signs")
            .as_slice()
            .try_into()
            .expect("fixed width");
        let forged = encode_signed(&wrong, &body_bytes);

        let raw = RawAttestation::decode(&forged).expect("decodes");
        assert_eq!(raw.verify(&key.public_key()).map(|_| ()), Err(Error::SignatureInvalid));
    }

    #[test]
    fn an_attestation_does_not_replay_across_networks() {
        let key = signer(9);
        let here = body(1, &key);
        let bytes = sign_attestation(&here, &key).expect("signs");
        let raw = RawAttestation::decode(&bytes).expect("decodes");

        // The same body, claiming another network: the signature covers the
        // network id, so it cannot be moved.
        let elsewhere =
            Attestation::new(1, here.heads.clone(), key.key_id(), NetworkId::from_bytes([8; 32]))
                .expect("bounded");
        let signature: [u8; limits::SIGNATURE_LEN] = key
            .sign(&attestation_signing_input(&network(), &here.encode()))
            .expect("signs")
            .as_slice()
            .try_into()
            .expect("fixed width");
        let moved = encode_signed(&signature, &elsewhere.encode());
        let raw_moved = RawAttestation::decode(&moved).expect("decodes");
        assert_eq!(raw_moved.verify(&key.public_key()).map(|_| ()), Err(Error::SignatureInvalid));
        assert!(raw.verify(&key.public_key()).is_ok(), "the original still verifies");
    }

    #[test]
    fn an_oversized_attestation_is_refused_before_it_is_parsed() {
        let huge = vec![0u8; limits::MAX_ATTESTATION_SIZE.saturating_add(1)];
        assert_eq!(
            RawAttestation::decode(&huge).map(|_| ()),
            Err(Error::LimitExceeded("attestation size"))
        );
    }

    #[test]
    fn too_many_heads_are_refused() {
        let key = signer(10);
        let heads = vec![head(1); limits::MAX_SNAPSHOT_HEADS.saturating_add(1)];
        assert_eq!(
            Attestation::new(1, heads, key.key_id(), network()).map(|_| ()),
            Err(Error::LimitExceeded("attestation heads"))
        );
    }
}

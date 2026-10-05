//! Snapshots: an admin's signed attestation that the state up to here is X.
//!
//! A snapshot is **not** an operation. It has no place in the DAG, is never
//! named as a parent, and never takes part in merge. That is the structural
//! reason DESIGN.md §4.6 can call a snapshot "not authoritative in a strong
//! sense" without needing a rule to enforce it: a snapshot cannot suppress an
//! operation, because it does not live in the graph the operations live in.
//!
//! Keeping it out also protects the closed set of seven operation types. Each
//! new type must be multiplied against the conflict rules of every existing
//! one, and for a snapshot that would mean deciding how two snapshots *merge* —
//! which §4.6 answers differently, with a monotone counter and refusal.
//!
//! # What a snapshot commits to
//!
//! ```text
//! Snapshot = { "seq": uint, "heads": [ bstr(32) ... ], "state": bstr,
//!              "author": bstr(32), "depths": [ uint ... ],
//!              "network": bstr(32) }
//! ```
//!
//! `author` names the key that signed, exactly as an operation's does. Without
//! it a verifier has to try every admin key in turn, which conflates two quite
//! different failures — a signature that does not verify, and a signer with no
//! authority — into one unhelpful answer.
//!
//! `depths` is the field easiest to think unnecessary and most damaging to
//! omit. Causal depth is the primary key of the last-writer-wins rule, so a
//! node that compacted and then guessed depths would resolve concurrent renames
//! differently from a node that kept its history — a fork that only appears
//! when two admins rename the same device at once.
//!
//! # A separate signing tag
//!
//! Snapshots sign under [`SNAPSHOT_DOMAIN_TAG`], never the operation tag. The
//! operation envelope's third component is an operation type drawn from a
//! closed set; smuggling snapshots through it would put a value in that
//! position that no operation may hold, which is the sort of near-miss a second
//! implementation gets wrong. Two tags make confusion structurally impossible
//! in both directions.

use crate::cbor::{Reader, Writer};
use crate::error::{Error, Result};
use crate::id::{KeyId, NetworkId, OperationId};
use crate::limits;
use crate::sign::{PublicKey, Signer};

/// Field names of a snapshot body, in canonical order.
pub const SNAPSHOT_SCHEMA: &[&str] = &["seq", "heads", "state", "author", "depths", "network"];

/// Field names of the signed snapshot wrapper, in canonical order.
pub const SIGNED_SNAPSHOT_SCHEMA: &[&str] = &["sig", "body"];

/// The version tag every snapshot signature is bound to.
///
/// Distinct from the operation tag so that neither kind of signature can be
/// made to verify as the other.
pub const SNAPSHOT_DOMAIN_TAG: &str = "roster-snapshot/v1";

/// Builds the byte string a snapshot signature covers.
///
/// Framed exactly as the operation envelope is: each variable-length component
/// preceded by its length as a big-endian `u16`, so no two component tuples can
/// concatenate to the same bytes.
#[must_use]
pub fn snapshot_signing_input(network: &NetworkId, body_bytes: &[u8]) -> Vec<u8> {
    let tag = SNAPSHOT_DOMAIN_TAG.as_bytes();
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

/// The body of a snapshot: what is signed, and what is hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Monotone sequence number. A node refuses anything that does not advance
    /// it, which is what stops a compromised rendezvous serving an old roster.
    pub seq: u64,
    /// Canonical bytes of the roster state derived from everything the heads
    /// cover — the output of `RosterState::to_bytes`.
    pub state: Vec<u8>,
    /// The id of the key that signed this snapshot.
    pub author: KeyId,
    /// The causal depth of each head, positionally matching `heads`.
    pub depths: Vec<u64>,
    /// The heads this snapshot covers. Its covered set is every causal ancestor
    /// of these, together with the heads themselves.
    pub heads: Vec<OperationId>,
    /// The network this snapshot belongs to.
    pub network: NetworkId,
}

impl Snapshot {
    /// Builds a snapshot body, checking its bounds and internal consistency.
    pub fn new(
        seq: u64,
        state: Vec<u8>,
        heads: Vec<OperationId>,
        depths: Vec<u64>,
        author: KeyId,
        network: NetworkId,
    ) -> Result<Self> {
        if heads.is_empty() {
            // A snapshot covering nothing attests to nothing.
            return Err(Error::MissingField);
        }
        if heads.len() != depths.len() {
            return Err(Error::MissingField);
        }
        if heads.len() > limits::MAX_SNAPSHOT_HEADS {
            return Err(Error::LimitExceeded("snapshot heads"));
        }
        if state.len() > limits::MAX_SNAPSHOT_SIZE {
            return Err(Error::LimitExceeded("snapshot size"));
        }
        Ok(Self { seq, state, author, depths, heads, network })
    }

    /// The depth recorded for a covered head.
    #[must_use]
    pub fn depth_of(&self, head: &OperationId) -> Option<u64> {
        let position = self.heads.iter().position(|candidate| candidate == head)?;
        self.depths.get(position).copied()
    }

    /// The greatest depth among the covered heads.
    ///
    /// Everything the snapshot covers sits at or below this, so every operation
    /// after it sits strictly above — which is what makes derivation compose
    /// across the boundary.
    #[must_use]
    pub fn frontier_depth(&self) -> u64 {
        self.depths.iter().copied().max().unwrap_or(0)
    }

    /// The canonical bytes of this body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.map(6);
        writer.key("seq").u64(self.seq);
        writer.key("heads").array(self.heads.len() as u64);
        for head in &self.heads {
            writer.bytes(head.as_bytes());
        }
        writer.key("state").bytes(&self.state);
        writer.key("author").bytes(self.author.as_bytes());
        writer.key("depths").array(self.depths.len() as u64);
        for depth in &self.depths {
            writer.u64(*depth);
        }
        writer.key("network").bytes(self.network.as_bytes());
        writer.finish()
    }

    /// Reads a body from its canonical bytes.
    ///
    /// Public for the reason [`crate::types::OperationCore::decode`] is: a body
    /// prepared and not yet signed is a thing somebody has to be **shown**
    /// before they authorise it, and what they are shown must be read from the
    /// bytes that will be signed rather than from a description sent beside
    /// them.
    ///
    /// # Errors
    ///
    /// When the bytes are not a canonical snapshot body.
    pub fn decode(body_bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(body_bytes);
        let mut map = reader.map(SNAPSHOT_SCHEMA)?;
        let seq = map.key("seq")?.u64()?;

        let heads_reader = map.key("heads")?;
        let head_count = heads_reader.array(limits::MAX_SNAPSHOT_HEADS, "snapshot heads")?;
        let mut heads = Vec::with_capacity(head_count);
        for _ in 0..head_count {
            heads.push(OperationId::decode(heads_reader)?);
        }

        let state = map.key("state")?.bytes(limits::MAX_SNAPSHOT_SIZE, "snapshot size")?.to_vec();
        let author = KeyId::decode(map.key("author")?)?;

        let depths_reader = map.key("depths")?;
        let depth_count = depths_reader.array(limits::MAX_SNAPSHOT_HEADS, "snapshot heads")?;
        let mut depths = Vec::with_capacity(depth_count);
        for _ in 0..depth_count {
            depths.push(depths_reader.u64()?);
        }

        let network = NetworkId::decode(map.key("network")?)?;
        map.finish()?;
        reader.finish()?;

        Self::new(seq, state, heads, depths, author, network)
    }
}

/// A decoded snapshot whose signature has not been checked.
///
/// Holds the received body bytes, not a re-encoding: verification runs over
/// exactly what arrived, for the same reason it does for operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSnapshot {
    /// The signature bytes.
    signature: [u8; limits::SIGNATURE_LEN],
    /// The exact received bytes of the signed body.
    body_bytes: Vec<u8>,
    /// The decoded body.
    body: Snapshot,
}

impl RawSnapshot {
    /// Decodes a snapshot.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > limits::MAX_SNAPSHOT_SIZE {
            return Err(Error::LimitExceeded("snapshot size"));
        }
        let mut reader = Reader::new(input);
        let mut map = reader.map(SIGNED_SNAPSHOT_SCHEMA)?;
        let signature_bytes = map.key("sig")?.fixed_bytes(limits::SIGNATURE_LEN)?;
        let body_bytes =
            map.key("body")?.bytes(limits::MAX_SNAPSHOT_SIZE, "snapshot size")?.to_vec();
        map.finish()?;
        reader.finish()?;

        let mut signature = [0u8; limits::SIGNATURE_LEN];
        signature.copy_from_slice(signature_bytes);
        let body = Snapshot::decode(&body_bytes)?;
        Ok(Self { signature, body_bytes, body })
    }

    /// The decoded body. Authentic only once [`Self::verify`] succeeds.
    #[must_use]
    pub const fn body(&self) -> &Snapshot {
        &self.body
    }

    /// The exact received bytes of the signed body.
    #[must_use]
    pub fn body_bytes(&self) -> &[u8] {
        &self.body_bytes
    }

    /// The signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; limits::SIGNATURE_LEN] {
        &self.signature
    }

    /// Re-encodes for forwarding, reproducing the received bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_signed(&self.signature, &self.body_bytes)
    }

    /// Checks the signature against `key`.
    ///
    /// Proves the snapshot was signed by the holder of that key over exactly
    /// these bytes. It proves nothing about whether the state it claims is
    /// true — that is [`crate::roster::Roster`]'s job, by deriving it.
    pub fn verify(&self, key: &PublicKey) -> Result<SignedSnapshot> {
        if key.key_id() != self.body.author {
            return Err(Error::AuthorKeyMismatch);
        }
        let message = snapshot_signing_input(&self.body.network, &self.body_bytes);
        key.verify(&message, &self.signature)?;
        Ok(SignedSnapshot {
            signature: self.signature,
            body_bytes: self.body_bytes.clone(),
            body: self.body.clone(),
            signer: self.body.author,
        })
    }
}

/// A snapshot whose signature has been checked against a public key.
///
/// Obtainable only through [`RawSnapshot::verify`], so a function taking this
/// type cannot be handed unchecked bytes. As with operations, this means
/// authentic — not that the state it states is the state that is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSnapshot {
    /// The signature bytes.
    signature: [u8; limits::SIGNATURE_LEN],
    /// The exact received bytes of the signed body.
    body_bytes: Vec<u8>,
    /// The decoded body.
    body: Snapshot,
    /// The key id that signed it.
    signer: KeyId,
}

impl SignedSnapshot {
    /// The snapshot body.
    #[must_use]
    pub const fn body(&self) -> &Snapshot {
        &self.body
    }

    /// The key that signed it.
    #[must_use]
    pub const fn signer(&self) -> KeyId {
        self.signer
    }

    /// The exact received body bytes.
    #[must_use]
    pub fn body_bytes(&self) -> &[u8] {
        &self.body_bytes
    }

    /// The signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; limits::SIGNATURE_LEN] {
        &self.signature
    }

    /// Encodes for transmission.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_signed(&self.signature, &self.body_bytes)
    }

    /// Whether two snapshots are the same attestation.
    ///
    /// Compared on the signed bytes rather than the signature, so re-signing
    /// the same content is not mistaken for a conflicting claim.
    #[must_use]
    pub fn same_content(&self, other: &Self) -> bool {
        self.body_bytes == other.body_bytes
    }
}

/// Writes the wire form of a signed snapshot.
fn encode_signed(signature: &[u8; limits::SIGNATURE_LEN], body_bytes: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.map(2);
    writer.key("sig").bytes(signature);
    writer.key("body").bytes(body_bytes);
    writer.finish()
}

/// Signs a snapshot body and produces the encoded artifact.
pub fn sign_snapshot(body: &Snapshot, signer: &dyn Signer) -> Result<Vec<u8>> {
    if signer.key_id() != body.author {
        // Signing under a key the body does not name would produce a snapshot
        // that could never verify.
        return Err(Error::AuthorKeyMismatch);
    }
    let body_bytes = body.encode();
    if body_bytes.len() > limits::MAX_SNAPSHOT_SIZE {
        return Err(Error::LimitExceeded("snapshot size"));
    }
    let message = snapshot_signing_input(&body.network, &body_bytes);
    let signature_bytes = signer.sign(&message)?;
    let signature: [u8; limits::SIGNATURE_LEN] =
        signature_bytes.as_slice().try_into().map_err(|_| Error::SignatureEncoding)?;
    Ok(encode_signed(&signature, &body_bytes))
}

/// Assembles a signed snapshot from parts that need not match.
///
/// For the corpus, which must be able to build snapshots whose signature does
/// not belong to their body so that every implementation can be shown refusing
/// them.
#[must_use]
pub fn assemble_snapshot(body_bytes: &[u8], signature: &[u8; limits::SIGNATURE_LEN]) -> Vec<u8> {
    encode_signed(signature, body_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;

    #[test]
    fn schemas_are_in_canonical_order() {
        assert!(cbor::is_canonical_schema(SNAPSHOT_SCHEMA));
        assert!(cbor::is_canonical_schema(SIGNED_SNAPSHOT_SCHEMA));
    }

    /// The tags must differ, or a signature over one kind could be made to
    /// verify as the other.
    #[test]
    fn the_snapshot_tag_differs_from_the_operation_tag() {
        assert_ne!(SNAPSHOT_DOMAIN_TAG, crate::sign::DOMAIN_TAG);
    }

    #[test]
    fn a_snapshot_without_heads_is_rejected() {
        assert_eq!(
            Snapshot::new(
                1,
                vec![],
                vec![],
                vec![],
                KeyId::from_bytes([3; 32]),
                NetworkId::from_bytes([1; 32])
            )
            .map(|_| ()),
            Err(Error::MissingField)
        );
    }

    #[test]
    fn heads_and_depths_must_correspond() {
        assert_eq!(
            Snapshot::new(
                1,
                vec![],
                vec![OperationId::from_bytes([2; 32])],
                vec![],
                KeyId::from_bytes([3; 32]),
                NetworkId::from_bytes([1; 32]),
            )
            .map(|_| ()),
            Err(Error::MissingField),
            "a head with no depth would leave the tie-break unanchored"
        );
    }

    #[test]
    fn too_many_heads_are_rejected() {
        let heads: Vec<OperationId> = (0..=limits::MAX_SNAPSHOT_HEADS)
            .map(|index| OperationId::from_bytes([u8::try_from(index % 256).unwrap_or(0); 32]))
            .collect();
        let depths = vec![1u64; heads.len()];
        assert_eq!(
            Snapshot::new(
                1,
                vec![],
                heads,
                depths,
                KeyId::from_bytes([3; 32]),
                NetworkId::from_bytes([1; 32]),
            )
            .map(|_| ()),
            Err(Error::LimitExceeded("snapshot heads"))
        );
    }

    #[test]
    fn depth_lookup_matches_position() {
        let body = Snapshot::new(
            3,
            vec![9],
            vec![OperationId::from_bytes([1; 32]), OperationId::from_bytes([2; 32])],
            vec![10, 20],
            KeyId::from_bytes([3; 32]),
            NetworkId::from_bytes([7; 32]),
        )
        .expect("well-formed");
        assert_eq!(body.depth_of(&OperationId::from_bytes([1; 32])), Some(10));
        assert_eq!(body.depth_of(&OperationId::from_bytes([2; 32])), Some(20));
        assert_eq!(body.depth_of(&OperationId::from_bytes([3; 32])), None);
        assert_eq!(body.frontier_depth(), 20);
    }
}

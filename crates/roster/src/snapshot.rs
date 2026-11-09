//! Snapshots: an admin's signed attestation that the state up to here is X.
//!
//! A snapshot is **not** an operation. It has no place in the DAG, is never
//! named as a parent, and never takes part in merge. That is the structural
//! reason DESIGN.md §4.6 can call a snapshot "not authoritative in a strong
//! sense" without needing a rule to enforce it: a snapshot cannot suppress an
//! operation, because it does not live in the graph the operations live in.
//!
//! Keeping it out also protects the closed set of operation types. Each new
//! type must be multiplied against the conflict rules of every existing one,
//! and for a snapshot that would mean deciding how two snapshots *merge*.
//!
//! # What a snapshot commits to
//!
//! A snapshot is a **root**: it commits to the state by its Merkle root, names
//! the roots it follows, and carries the proof that its signer was an admin in
//! the first of them.
//!
//! ```text
//! Snapshot = { "root": bstr(32), "delta": [ bstr(32) ... ],
//!              "heads": [ bstr(32) ... ], "proof": MembershipProof,
//!              "author": bstr(32), "depths": [ uint ... ],
//!              "signer": DeviceLeaf, "network": bstr(32),
//!              "previous": [ bstr(32) ... ], "generation": uint }
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
use crate::id::{DeviceId, KeyId, NetworkId, OperationId};
use crate::leaf::DeviceLeaf;
use crate::limits;
use crate::membership::MembershipProof;
use crate::merkle::Hash;
use crate::prelude::*;
use crate::sign::{PublicKey, Signer};
use crate::state::RosterState;

/// Field names of a snapshot body, in canonical order.
pub const SNAPSHOT_SCHEMA: &[&str] = &[
    "root",
    "delta",
    "heads",
    "proof",
    "author",
    "depths",
    "signer",
    "network",
    "previous",
    "generation",
];

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

/// The body of a snapshot — a **root**: what is signed, and what is hashed.
///
/// It commits to the roster state by its Merkle root rather than by carrying
/// the state, so it is the same size for five devices or five million. The
/// state itself travels as leaves, each provable against [`Self::root`].
///
/// A root follows the root or roots it names in [`Self::previous`], and its
/// signer proves, against the first of those, that it was an admin there: a
/// member holding no roster checks a root with the root before it and nothing
/// else. A root that follows nothing — the first — proves its signer against
/// itself, and is trusted the way a first root always is: by how it arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// One more than the highest generation among the roots it follows; 1 for
    /// a root that follows nothing.
    pub generation: u64,
    /// The state roots of the roots this one follows, sorted, without repeats.
    pub previous: Vec<Hash>,
    /// The root of the state everything the heads cover derives.
    pub root: Hash,
    /// The causal depth of each head, positionally matching `heads`.
    pub depths: Vec<u64>,
    /// The heads this snapshot covers. Its covered set is every causal ancestor
    /// of these, together with the heads themselves.
    pub heads: Vec<OperationId>,
    /// The devices whose leaf in the root it follows this root no longer holds
    /// as it was: revoked, or changed in any way. Sorted, without repeats.
    /// Admissions are not listed: they invalidate no earlier proof.
    pub delta: Vec<DeviceId>,
    /// The signer's leaf, as the root it follows holds it.
    pub signer: DeviceLeaf,
    /// The proof of [`Self::signer`] against the first previous root, or
    /// against [`Self::root`] when there is none.
    pub proof: MembershipProof,
    /// The id of the key that signed, one of [`Self::signer`]'s keys.
    pub author: KeyId,
    /// The network this snapshot belongs to.
    pub network: NetworkId,
}

/// The parts of a snapshot that come from the graph rather than from the
/// state: which heads it covers and how deep each is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Covering {
    /// The heads.
    pub heads: Vec<OperationId>,
    /// Their depths, positionally matching.
    pub depths: Vec<u64>,
}

impl Snapshot {
    /// Builds a snapshot body, checking its bounds and internal consistency.
    ///
    /// # Errors
    ///
    /// When it covers no heads, a head has no depth, the bounds are exceeded,
    /// the lists are out of order, or the author is not one of the signer's
    /// keys.
    #[allow(clippy::too_many_arguments, reason = "every field of the format, checked once")]
    pub fn new(
        generation: u64,
        previous: Vec<Hash>,
        root: Hash,
        covering: Covering,
        delta: Vec<DeviceId>,
        signer: DeviceLeaf,
        proof: MembershipProof,
        author: KeyId,
        network: NetworkId,
    ) -> Result<Self> {
        let Covering { heads, depths } = covering;
        if heads.is_empty() {
            // A snapshot covering nothing attests to nothing.
            return Err(Error::MissingField);
        }
        if heads.len() != depths.len() {
            return Err(Error::MissingField);
        }
        if heads.len() > limits::MAX_SNAPSHOT_HEADS || previous.len() > limits::MAX_SNAPSHOT_HEADS {
            return Err(Error::LimitExceeded("snapshot heads"));
        }
        if delta.len() > limits::MAX_OPERATIONS {
            return Err(Error::LimitExceeded("snapshot delta"));
        }
        if generation == 0 || (previous.is_empty() != (generation == 1)) {
            return Err(Error::InvalidValue("snapshot generation"));
        }
        if !strictly_ascending(&previous) || !strictly_ascending(&delta) {
            return Err(Error::NonCanonical);
        }
        if !signer.record.keys.iter().any(|entry| entry.key_id() == author) {
            return Err(Error::AuthorKeyMismatch);
        }
        Ok(Self {
            generation,
            previous,
            root,
            depths,
            heads,
            delta,
            signer,
            proof,
            author,
            network,
        })
    }

    /// The snapshot of `state` covering `covering`, signed by the device
    /// holding `author`, following `previous` when there is one.
    ///
    /// The signer is proved in the previous state, which is what a member that
    /// holds only the previous root can check; the delta is everything the
    /// previous state held that this one no longer holds as it was.
    ///
    /// # Errors
    ///
    /// When the signer is not an admin in the state it is proved in, or the
    /// body is not well formed.
    pub fn over(
        state: &RosterState,
        covering: Covering,
        author: KeyId,
        previous: Option<(&Self, &RosterState)>,
    ) -> Result<Self> {
        let proved_in = previous.map_or(state, |(_, before)| before);
        let device = proved_in.device_holding(&author).ok_or(Error::UnauthorizedAuthor)?;
        let signer = proved_in.leaf(&device).ok_or(Error::UnauthorizedAuthor)?;
        if signer.record.role != crate::types::Role::Admin {
            return Err(Error::UnauthorizedAuthor);
        }
        let proof = MembershipProof::of(proved_in, &device).ok_or(Error::UnauthorizedAuthor)?;
        let (generation, previous_roots, delta) = match previous {
            Some((before, before_state)) => (
                before.generation.saturating_add(1),
                alloc::vec![before.root],
                state.delta_from(before_state),
            ),
            None => (1, Vec::new(), Vec::new()),
        };
        Self::new(
            generation,
            previous_roots,
            state.root(),
            covering,
            delta,
            signer,
            proof,
            author,
            state.network,
        )
    }

    /// Whether the signer is proved an admin against `previous_root` — the
    /// first root this one follows, or its own root when it follows none.
    #[must_use]
    pub fn signer_proved(&self, previous_root: &Hash) -> bool {
        self.signer.record.role == crate::types::Role::Admin
            && self.proof.verifies(previous_root, &self.network, &self.signer)
    }

    /// The root the signer's proof is against: the first previous root, or
    /// this root.
    #[must_use]
    pub fn proved_against(&self) -> Hash {
        self.previous.first().copied().unwrap_or(self.root)
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
        writer.map(10);
        writer.key("root").bytes(&self.root);
        writer.key("delta").array(self.delta.len() as u64);
        for device in &self.delta {
            device.encode(&mut writer);
        }
        writer.key("heads").array(self.heads.len() as u64);
        for head in &self.heads {
            writer.bytes(head.as_bytes());
        }
        writer.key("proof");
        self.proof.encode(&mut writer);
        writer.key("author").bytes(self.author.as_bytes());
        writer.key("depths").array(self.depths.len() as u64);
        for depth in &self.depths {
            writer.u64(*depth);
        }
        writer.key("signer");
        self.signer.encode(&mut writer);
        writer.key("network").bytes(self.network.as_bytes());
        writer.key("previous").array(self.previous.len() as u64);
        for root in &self.previous {
            writer.bytes(root);
        }
        writer.key("generation").u64(self.generation);
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
        let root = hash(map.key("root")?)?;

        let delta_reader = map.key("delta")?;
        let delta_count = delta_reader.array(limits::MAX_OPERATIONS, "snapshot delta")?;
        let mut delta = Vec::with_capacity(delta_count);
        for _ in 0..delta_count {
            delta.push(DeviceId::decode(delta_reader)?);
        }

        let heads_reader = map.key("heads")?;
        let head_count = heads_reader.array(limits::MAX_SNAPSHOT_HEADS, "snapshot heads")?;
        let mut heads = Vec::with_capacity(head_count);
        for _ in 0..head_count {
            heads.push(OperationId::decode(heads_reader)?);
        }

        let proof = MembershipProof::decode(map.key("proof")?)?;
        let author = KeyId::decode(map.key("author")?)?;

        let depths_reader = map.key("depths")?;
        let depth_count = depths_reader.array(limits::MAX_SNAPSHOT_HEADS, "snapshot heads")?;
        let mut depths = Vec::with_capacity(depth_count);
        for _ in 0..depth_count {
            depths.push(depths_reader.u64()?);
        }

        let signer = DeviceLeaf::decode(map.key("signer")?)?;
        let network = NetworkId::decode(map.key("network")?)?;

        let previous_reader = map.key("previous")?;
        let previous_count = previous_reader.array(limits::MAX_SNAPSHOT_HEADS, "snapshot heads")?;
        let mut previous = Vec::with_capacity(previous_count);
        for _ in 0..previous_count {
            previous.push(hash(previous_reader)?);
        }

        let generation = map.key("generation")?.u64()?;
        map.finish()?;
        reader.finish()?;

        Self::new(
            generation,
            previous,
            root,
            Covering { heads, depths },
            delta,
            signer,
            proof,
            author,
            network,
        )
    }
}

/// Reads a 32-byte hash.
fn hash(reader: &mut Reader<'_>) -> Result<Hash> {
    Hash::try_from(reader.fixed_bytes(32)?).map_err(|_| Error::IdentifierLength)
}

/// Whether every item is greater than the one before it.
fn strictly_ascending<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| matches!(pair, [first, second] if first < second))
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
}

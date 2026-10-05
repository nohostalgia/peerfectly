//! Proving that one device holds both of the keys it presented.
//!
//! The channel proves the **transport** key: the admitting side dials that key,
//! and nobody who does not hold it can answer. It proves nothing about the
//! **signing** key, which is only a field in a payload that is public.
//!
//! That gap matters because a device's identity is derived from its signing key.
//! A payload pairing one device's signing key with an attacker's transport key
//! would have an admin sign an operation binding that identity — and that
//! overlay address — to the attacker. Worse, a roster keeps the **first**
//! admission of a device id and ignores later ones, so the real holder of that
//! signing key could never afterwards be admitted under its own identity. The
//! damage would not be repairable.
//!
//! So the joining device signs the exchange's channel material with its signing
//! key, and the admitting side verifies that signature against the signing key
//! the payload carries. One signature, one verification, no extra round trip —
//! the channel material already exists for the confirmation code — and because
//! the signature covers that material it cannot be gathered on one channel and
//! presented on another.

use roster::cbor::{Reader, Writer};
use roster::sign::{PublicKey, Signer};

use crate::error::{Error, Result};
use crate::limits;

/// The derivation context for a proof of possession.
///
/// Domain separation, and here it does real work: without it a signature made
/// for some other purpose in this system might serve as this proof, or this
/// proof might serve somewhere else. The joining device is signing bytes chosen
/// by whoever it is talking to, which is exactly the situation domain separation
/// exists for.
pub const DOMAIN_POSSESSION: &str = "peerfectly enrolment possession v1";

/// A joining device's proof that it holds the signing key it presented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Possession {
    /// The signature over this exchange's derived challenge.
    signature: Vec<u8>,
}

impl Possession {
    /// Signs this exchange's challenge with the device's signing key.
    ///
    /// # Errors
    ///
    /// When the channel material is empty, or the signer refuses.
    pub fn prove(signer: &dyn Signer, channel: &[u8]) -> Result<Self> {
        let challenge = challenge(channel)?;
        Ok(Self { signature: signer.sign(&challenge)? })
    }

    /// The request a custodian signs to prove possession of `signing`.
    ///
    /// Its bytes are exactly the challenge [`Self::prove`] signs, so a proof made
    /// through it verifies exactly as one signed directly.
    ///
    /// # Errors
    ///
    /// When the channel material is empty.
    pub fn request(
        signing: &PublicKey,
        channel: &[u8],
    ) -> Result<identity::detached::SigningRequest> {
        let challenge = challenge(channel)?;
        Ok(identity::detached::prepare_possession(&challenge, signing))
    }

    /// Proves possession through whichever path the identity's signing key takes.
    ///
    /// A key held in this process signs as [`Self::prove`] does. A key held by a
    /// custodian — a phone's keystore — signs through the detached path, so its
    /// private material never enters this process, and a person declining the
    /// prompt comes back as the custodian's own refusal.
    ///
    /// # Errors
    ///
    /// When the channel material is empty, or the identity's key does not sign.
    pub fn prove_detached(identity: &identity::NodeIdentity, channel: &[u8]) -> Result<Self> {
        let request = Self::request(&identity.signing_key().public_key(), channel)?;
        let signature = identity.sign_request(&request).map_err(Error::NotProved)?;
        Ok(Self { signature })
    }

    /// Checks the proof against the signing key a payload named.
    ///
    /// # Errors
    ///
    /// [`Error::PossessionUnproved`] when the signature does not verify, which
    /// is the same answer for a forged proof, a proof for another channel, and a
    /// payload whose two keys belong to two different devices. A caller learns
    /// only that this device must not be admitted, which is all it needs.
    pub fn verify(&self, signing: &PublicKey, channel: &[u8]) -> Result<()> {
        let challenge = challenge(channel)?;
        signing.verify(&challenge, &self.signature).map_err(|_| Error::PossessionUnproved)
    }

    /// The signature, for putting on the wire.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.signature
    }

    /// Takes a proof from the wire.
    ///
    /// Nothing is checked here: a signature is bytes until it is verified
    /// against a key and a channel, and pretending otherwise would invite a
    /// caller to believe this constructor had decided something.
    #[must_use]
    pub fn from_bytes(signature: Vec<u8>) -> Self {
        Self { signature }
    }
}

/// What a joining device signs: this channel, and nothing else.
fn challenge(channel: &[u8]) -> Result<[u8; 32]> {
    if channel.is_empty() {
        return Err(Error::Malformed("a proof of possession needs channel material"));
    }
    Ok(blake3::derive_key(DOMAIN_POSSESSION, channel))
}

/// Field names of the envelope every message travels in, in canonical order.
pub const ENVELOPE_SCHEMA: &[&str] = &["body", "kind"];

/// Field names of the joining device's opening message.
pub const HELLO_SCHEMA: &[&str] = &["kind", "proof"];

/// Field names of the admitting side's delivery.
pub const ADMISSION_SCHEMA: &[&str] = &["kind", "roster", "snapshot"];

/// Field names of the joining device's statement that the code matched.
pub const ACCEPTED_SCHEMA: &[&str] = &["kind"];

/// Field names of the joining device's answer.
pub const OUTCOME_SCHEMA: &[&str] = &["kind", "taken"];

/// What one side says to the other.
///
/// Four messages, in one order, and each side knows which it expects. A message
/// arriving out of turn is refused rather than acted on: an exchange with no
/// fixed shape is one where an attacker chooses the shape.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
    /// Joiner to admitting side: the proof that it holds its signing key.
    ///
    /// It carries no payload. The admitting side already read one, and the
    /// channel it dialled proves the transport key in it; a second copy here
    /// would be a second source for one fact, which is a thing to disagree with.
    Hello {
        /// The proof over this exchange's channel material.
        possession: Possession,
    },

    /// Joiner to admitting side: the code a person entered matched.
    ///
    /// It carries nothing. Both sides computed the same code from the channel,
    /// so a field repeating it would be a second source for one fact — and
    /// sending the digits a person typed would put them on the channel, which is
    /// what an attacker who dialled the waiting device first controls.
    ///
    /// What it carries is *timing*: until this arrives, the admitting side does
    /// not know whether anybody compared anything, and signing before it would
    /// deliver the whole roster to a device whose person has confirmed nothing.
    Accepted,

    /// Admitting side to joiner: the network, after a person confirmed.
    ///
    /// Signed operations, so what they are worth does not depend on this being
    /// the side that sent them.
    Admission {
        /// The operations the joiner must verify before believing any of them.
        operations: Vec<Vec<u8>>,
        /// The network's current snapshot, where the admitting side holds one.
        ///
        /// Optional, and absent has one meaning: the admitting side had none to
        /// send. A joiner that received none is a member with nothing to measure
        /// freshness from — which is the same state a device reaches when it has
        /// been out of touch too long, so the two must not be confused by a
        /// device that simply arrived.
        ///
        /// It is not evidence of anything. Like the operations beside it, it is
        /// signed, and what it is worth is decided by checking it rather than by
        /// who sent it.
        snapshot: Option<Vec<u8>>,
    },

    /// Joiner to admitting side: whether it adopted what arrived.
    ///
    /// A courtesy, so the admitting side can tell a person what happened. It is
    /// not evidence of anything: the admitting side has already signed, and it
    /// must not treat this as the confirmation its own person gave.
    Outcome {
        /// Whether the network was adopted.
        taken: bool,
    },
}

impl Message {
    /// The wire name of this message's kind.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "hello",
            Self::Accepted => "accepted",
            Self::Admission { .. } => "admit",
            Self::Outcome { .. } => "outcome",
        }
    }

    /// Writes the canonical bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let body = match self {
            Self::Hello { possession } => {
                let mut writer = Writer::new();
                writer.map(2);
                writer.key("kind").str("hello");
                writer.key("proof").bytes(possession.as_bytes());
                writer.finish()
            }
            Self::Accepted => {
                let mut writer = Writer::new();
                writer.map(1);
                writer.key("kind").str("accepted");
                writer.finish()
            }
            Self::Admission { operations, snapshot } => {
                let mut writer = Writer::new();
                // Absence has one spelling: the key is not written. A null would
                // be a second way to say the same thing, and two spellings of one
                // fact are two things for implementations to disagree about.
                writer.map(if snapshot.is_some() { 3 } else { 2 });
                writer.key("kind").str("admit");
                writer.key("roster").array(operations.len() as u64);
                for operation in operations {
                    writer.bytes(operation);
                }
                if let Some(snapshot) = snapshot {
                    writer.key("snapshot").bytes(snapshot);
                }
                writer.finish()
            }
            Self::Outcome { taken } => {
                let mut writer = Writer::new();
                writer.map(2);
                writer.key("kind").str("outcome");
                writer.key("taken").bool(*taken);
                writer.finish()
            }
        };

        let mut writer = Writer::new();
        writer.map(2);
        writer.key("body").bytes(&body);
        writer.key("kind").str(self.kind());
        writer.finish()
    }

    /// Reads canonical bytes, refusing anything else.
    ///
    /// # Errors
    ///
    /// When the bytes are not exactly one message, when a length exceeds its
    /// bound, or when the envelope's kind does not match the body's — which
    /// would be a message claiming to be one thing and carrying another.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > limits::MAX_EXCHANGE_MESSAGE_SIZE {
            return Err(Error::TooLong {
                field: "exchange message",
                len: input.len(),
                limit: limits::MAX_EXCHANGE_MESSAGE_SIZE,
            });
        }

        let mut reader = Reader::new(input);
        let mut envelope = reader.map(ENVELOPE_SCHEMA)?;
        let body = envelope
            .key("body")?
            .bytes(limits::MAX_EXCHANGE_MESSAGE_SIZE, "message body")?
            .to_vec();
        let stated = envelope.key("kind")?.str(16, "message kind")?.to_owned();
        envelope.finish()?;
        reader.finish()?;

        let message = Self::decode_body(&stated, &body, input.len())?;
        if message.kind() != stated {
            return Err(Error::Malformed("the envelope names a different message than it carries"));
        }
        Ok(message)
    }

    /// Reads one message body, given what the envelope claims it is.
    fn decode_body(kind: &str, body: &[u8], available: usize) -> Result<Self> {
        let mut reader = Reader::new(body);
        match kind {
            "hello" => {
                let mut map = reader.map(HELLO_SCHEMA)?;
                if map.key("kind")?.str(16, "message kind")? != "hello" {
                    return Err(Error::Malformed("the body names a different message"));
                }
                let proof =
                    map.key("proof")?.bytes(roster::limits::SIGNATURE_LEN, "proof")?.to_vec();
                map.finish()?;
                reader.finish()?;
                Ok(Self::Hello { possession: Possession::from_bytes(proof) })
            }
            "accepted" => {
                let mut map = reader.map(ACCEPTED_SCHEMA)?;
                if map.key("kind")?.str(16, "message kind")? != "accepted" {
                    return Err(Error::Malformed("the body names a different message"));
                }
                map.finish()?;
                reader.finish()?;
                Ok(Self::Accepted)
            }
            "admit" => {
                let mut map = reader.map_with_optional(ADMISSION_SCHEMA, &["snapshot"])?;
                if map.key("kind")?.str(16, "message kind")? != "admit" {
                    return Err(Error::Malformed("the body names a different message"));
                }
                let value = map.key("roster")?;
                let declared = value.array(roster::limits::MAX_OPERATIONS, "operations")?;
                // Every operation costs at least one byte, so a count larger
                // than the whole message cannot be honest. Checked before
                // anything is reserved, and nothing is reserved to it anyway.
                if declared > available {
                    return Err(Error::Malformed("more operations declared than could be carried"));
                }
                let mut operations = Vec::new();
                for _ in 0..declared {
                    operations.push(
                        value.bytes(roster::limits::MAX_OPERATION_SIZE, "operation")?.to_vec(),
                    );
                }
                let snapshot = match map.optional_key("snapshot")? {
                    Some(value) => {
                        Some(value.bytes(roster::limits::MAX_OPERATION_SIZE, "snapshot")?.to_vec())
                    }
                    None => None,
                };
                map.finish()?;
                reader.finish()?;
                Ok(Self::Admission { operations, snapshot })
            }
            "outcome" => {
                let mut map = reader.map(OUTCOME_SCHEMA)?;
                if map.key("kind")?.str(16, "message kind")? != "outcome" {
                    return Err(Error::Malformed("the body names a different message"));
                }
                let taken = map.key("taken")?.bool()?;
                map.finish()?;
                reader.finish()?;
                Ok(Self::Outcome { taken })
            }
            _ => Err(Error::Malformed("an exchange message of a kind this version does not speak")),
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use identity::NodeIdentity;

    use super::*;

    #[test]
    fn a_device_proves_the_key_it_holds() {
        let device = NodeIdentity::generate().expect("generates");
        let channel = b"one exchange";

        let proof = Possession::prove(device.signing_key().signer(), channel).expect("signs");
        proof
            .verify(&device.signing_key().public_key(), channel)
            .expect("the holder's own key verifies");
    }

    /// The attack this exists for: a payload naming one device's signing key
    /// beside another's transport key. The channel authenticates the transport
    /// key, so only this catches it.
    #[test]
    fn a_payload_mixing_two_devices_keys_is_refused() {
        let victim = NodeIdentity::generate().expect("generates");
        let attacker = NodeIdentity::generate().expect("generates");
        let channel = b"the attacker's exchange";

        // The attacker holds its own keys and can sign with them, but the
        // payload it substituted names the victim's signing key.
        let proof = Possession::prove(attacker.signing_key().signer(), channel).expect("signs");

        assert!(matches!(
            proof.verify(&victim.signing_key().public_key(), channel),
            Err(Error::PossessionUnproved)
        ));
    }

    /// A proof is bound to the channel it was made on, so one gathered
    /// elsewhere — or replayed from an earlier exchange — is worthless.
    #[test]
    fn a_proof_does_not_transfer_to_another_exchange() {
        let device = NodeIdentity::generate().expect("generates");
        let proof = Possession::prove(device.signing_key().signer(), b"one").expect("signs");

        assert!(matches!(
            proof.verify(&device.signing_key().public_key(), b"another"),
            Err(Error::PossessionUnproved)
        ));
    }

    /// The transport key is what the channel proves. It must not be able to
    /// stand in for the signing key here.
    #[test]
    fn the_transport_key_does_not_prove_the_signing_key() {
        let device = NodeIdentity::generate().expect("generates");
        let channel = b"one exchange";

        let proof = Possession::prove(device.transport_key().signer(), channel).expect("signs");

        assert!(matches!(
            proof.verify(&device.signing_key().public_key(), channel),
            Err(Error::PossessionUnproved)
        ));
    }

    #[test]
    fn a_forged_proof_is_refused() {
        let device = NodeIdentity::generate().expect("generates");
        let channel = b"one exchange";
        let proof = Possession::from_bytes(vec![0u8; 64]);

        assert!(matches!(
            proof.verify(&device.signing_key().public_key(), channel),
            Err(Error::PossessionUnproved)
        ));
    }

    #[test]
    fn a_proof_needs_channel_material() {
        let device = NodeIdentity::generate().expect("generates");
        assert!(Possession::prove(device.signing_key().signer(), &[]).is_err());
    }

    fn hello() -> Message {
        let device = NodeIdentity::generate().expect("generates");
        let possession =
            Possession::prove(device.signing_key().signer(), b"one exchange").expect("signs");
        Message::Hello { possession }
    }

    fn messages() -> Vec<Message> {
        vec![
            hello(),
            Message::Admission { operations: vec![vec![1, 2, 3], vec![4, 5]], snapshot: None },
            Message::Admission { operations: Vec::new(), snapshot: None },
            // Both spellings of the snapshot field, because absence is a
            // spelling: the key is simply not written.
            Message::Admission {
                operations: vec![vec![1, 2, 3]],
                snapshot: Some(vec![9, 8, 7, 6]),
            },
            Message::Admission { operations: Vec::new(), snapshot: Some(Vec::new()) },
            Message::Accepted,
            Message::Outcome { taken: true },
            Message::Outcome { taken: false },
        ]
    }

    #[test]
    fn every_message_round_trips() {
        for message in messages() {
            let bytes = message.encode();
            let recovered = Message::decode(&bytes).expect("decodes");
            assert_eq!(recovered, message);
            assert_eq!(recovered.encode(), bytes, "one message, one byte sequence");
        }
    }

    /// It says one thing and carries nothing, which is the whole of it: the
    /// admitting side learns that a person compared, and learns it at a moment
    /// rather than by being told a value it already has.
    #[test]
    fn the_acceptance_carries_nothing_but_its_kind() {
        let bytes = Message::Accepted.encode();
        assert_eq!(Message::decode(&bytes).expect("decodes"), Message::Accepted);

        // One key in the body, and it is the kind. A field here would be a
        // second source for a value both sides already computed.
        let mut reader = roster::cbor::Reader::new(&bytes);
        let mut envelope = reader.map(ENVELOPE_SCHEMA).expect("an envelope");
        let body =
            envelope.key("body").expect("a body").bytes(256, "body").expect("bytes").to_vec();
        let mut inner = roster::cbor::Reader::new(&body);
        let mut map = inner.map(ACCEPTED_SCHEMA).expect("the body's map");
        assert_eq!(map.key("kind").expect("kind").str(16, "kind").expect("text"), "accepted");
        map.finish().expect("nothing else in it");
    }

    #[test]
    fn the_schemas_are_in_canonical_key_order() {
        for schema in
            [ENVELOPE_SCHEMA, HELLO_SCHEMA, ACCEPTED_SCHEMA, ADMISSION_SCHEMA, OUTCOME_SCHEMA]
        {
            assert!(roster::cbor::is_canonical_schema(schema), "{schema:?}");
        }
    }

    /// A message that says it is one thing and carries another is refused. The
    /// alternative is a reader that trusts the label over the contents, which is
    /// how a parser is talked into the wrong branch.
    #[test]
    fn an_envelope_that_lies_about_its_body_is_refused() {
        let mut writer = Writer::new();
        writer.map(2);
        writer.key("body").bytes(&{
            let mut body = Writer::new();
            body.map(2);
            body.key("kind").str("outcome");
            body.key("taken").bool(true);
            body.finish()
        });
        writer.key("kind").str("hello");
        let lying = writer.finish();

        assert!(matches!(Message::decode(&lying), Err(Error::Malformed(_))));
    }

    /// The acceptance has one field and no room for another. A body carrying
    /// more is refused rather than read for the part that was expected: a
    /// message with optional extras is a message whose meaning depends on who
    /// wrote it.
    #[test]
    fn an_acceptance_carrying_anything_else_is_refused() {
        let mut body = Writer::new();
        body.map(2);
        body.key("kind").str("accepted");
        body.key("taken").bool(true);
        let body = body.finish();

        let mut writer = Writer::new();
        writer.map(2);
        writer.key("body").bytes(&body);
        writer.key("kind").str("accepted");

        assert!(Message::decode(&writer.finish()).is_err());
    }

    /// And an acceptance's body under another kind's envelope, which is the
    /// same lie the test above tells in the other direction.
    #[test]
    fn an_envelope_claiming_an_acceptance_it_does_not_carry_is_refused() {
        let mut writer = Writer::new();
        writer.map(2);
        writer.key("body").bytes(&{
            let mut body = Writer::new();
            body.map(1);
            body.key("kind").str("accepted");
            body.finish()
        });
        writer.key("kind").str("hello");

        // Refused on the body, which does not have the shape a greeting needs,
        // rather than on the mismatch that would have been found after it.
        // Either way it never decodes.
        Message::decode(&writer.finish()).expect_err("a lie is refused");
    }

    #[test]
    fn a_message_kind_this_version_does_not_speak_is_refused() {
        let mut writer = Writer::new();
        writer.map(2);
        writer.key("body").bytes(&[0xa0]);
        writer.key("kind").str("negotiate");
        let unknown = writer.finish();

        assert!(matches!(Message::decode(&unknown), Err(Error::Malformed(_))));
    }

    #[test]
    fn trailing_bytes_and_truncation_are_both_refused() {
        let bytes = Message::Outcome { taken: true }.encode();

        let mut extra = bytes.clone();
        extra.push(0x00);
        assert!(Message::decode(&extra).is_err(), "trailing bytes must be refused");

        for cut in 0..bytes.len() {
            let Some(short) = bytes.get(..cut) else { continue };
            assert!(Message::decode(short).is_err(), "a message cut at {cut} was accepted");
        }
    }

    /// A count is checked against what could possibly be carried before
    /// anything is reserved for it, so a peer cannot make this allocate by
    /// claiming a large number.
    #[test]
    fn an_operation_count_larger_than_the_message_is_refused() {
        let mut body = Writer::new();
        body.map(2);
        body.key("kind").str("admit");
        body.key("roster").array(4000);
        let body = body.finish();

        let mut writer = Writer::new();
        writer.map(2);
        writer.key("body").bytes(&body);
        writer.key("kind").str("admit");

        assert!(Message::decode(&writer.finish()).is_err());
    }

    /// The challenge is domain-separated, so what a device signs here cannot be
    /// mistaken for anything it signs elsewhere.
    #[test]
    fn the_challenge_is_not_the_channel_material() {
        let channel = b"one exchange";
        let derived = challenge(channel).expect("derives");
        assert_ne!(derived.as_slice(), channel.as_slice());
        assert_ne!(derived, blake3::derive_key("some other context", channel));
    }
}

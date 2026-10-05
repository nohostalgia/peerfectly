//! What a joining device shows, and how it travels.
//!
//! # It is public
//!
//! This is displayed on a screen, photographed, and pasted into whatever channel
//! a person finds convenient. It carries no secret and grants nothing: it says
//! who is asking and where they are waiting, and asking is free. Everything that
//! makes an enrolment safe is checked elsewhere and does not depend on these
//! bytes having travelled privately.
//!
//! # It cannot ask for a role
//!
//! A payload carries keys and a *proposed* name. It carries no role, no founder
//! flag and no capabilities, so a device cannot ask to be an admin — the admin
//! that admits it decides what it is permitted to be. This is also why the
//! payload is not a `DeviceSpec`: moving a structure whose most dangerous fields
//! must be ignored on arrival is an invitation to stop ignoring them.
//!
//! # Encoding
//!
//! The roster's canonical CBOR, not a second encoder: definite lengths, minimal
//! integer widths, length-first map key ordering, every field exactly once, no
//! trailing bytes, and rejection rather than repair.

use roster::cbor::{Reader, Writer};
use roster::sign::PublicKey;
use roster::types::Algorithm;

use crate::error::{Error, Result};
use crate::limits;

/// The text form's prefix, which is also its version.
///
/// A person sees this and knows what they are holding. A future format changes
/// the prefix, so an old reader refuses new bytes rather than misreading them.
pub const TEXT_PREFIX: &str = "peerfectly-join-v1:";

/// Field names of a joining payload, in canonical order.
///
/// Public so a second implementation can assert its own field order against this
/// one instead of transcribing `FORMAT.md` by eye.
pub const JOINING_SCHEMA: &[&str] = &["alg", "name", "sign", "relay", "trans", "attest"];

/// What a device with no network shows, so that it can be given one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Joining {
    /// The device's signing key. Its identity is derived from this.
    pub signing: PublicKey,
    /// The device's transport key. Sessions are authenticated by this.
    pub transport: PublicKey,
    /// The device's attestation key, which will date the roster it is given.
    ///
    /// Carried here because the device record the admission signs must contain
    /// it, and the admitting side has nowhere else to learn it from. It is
    /// covered by the confirmation code, so it cannot be substituted in flight
    /// without the digits changing.
    pub attestation: PublicKey,
    /// The name the device proposes for itself. The admin may choose another.
    pub name: String,
    /// The relay at which the device is waiting to be reached.
    pub relay: String,
}

impl Joining {
    /// Builds a payload, checking every bound.
    ///
    /// # Errors
    ///
    /// When the name or the relay is empty or longer than its bound. Empty is
    /// refused rather than accepted and ignored: a device with no name and a
    /// device asking for the empty name are not the same request.
    pub fn new(
        signing: PublicKey,
        transport: PublicKey,
        attestation: PublicKey,
        name: impl Into<String>,
        relay: impl Into<String>,
    ) -> Result<Self> {
        let name = name.into();
        let relay = relay.into();

        if name.is_empty() {
            return Err(Error::Empty("proposed name"));
        }
        if name.len() > limits::MAX_PROPOSED_NAME_LEN {
            return Err(Error::TooLong {
                field: "proposed name",
                len: name.len(),
                limit: limits::MAX_PROPOSED_NAME_LEN,
            });
        }
        if relay.is_empty() {
            return Err(Error::Empty("relay address"));
        }
        if relay.len() > limits::MAX_RELAY_LEN {
            return Err(Error::TooLong {
                field: "relay address",
                len: relay.len(),
                limit: limits::MAX_RELAY_LEN,
            });
        }
        Ok(Self { signing, transport, attestation, name, relay })
    }

    /// What this device would show, taken from its own identity.
    ///
    /// # Errors
    ///
    /// When the name or the relay is outside its bound.
    pub fn of(
        identity: &identity::NodeIdentity,
        name: impl Into<String>,
        relay: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            identity.signing_key().public_key(),
            identity.transport_key().public_key(),
            identity.attestation_key().public_key(),
            name,
            relay,
        )
    }

    /// Writes the canonical bytes.
    ///
    /// Neither the transport key's algorithm nor the attestation key's is
    /// carried: §2.3 fixes device transport keys as ed25519 and
    /// `transport-iroh` refuses anything else at bind, and an attestation key is
    /// ed25519 for a reason of its own — it is never held in an enclave, because
    /// a key in one is a key that asks. The signing key's algorithm is carried,
    /// because a root key in a phone's enclave is P-256.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.map(6);
        writer.key("alg").str(self.signing.algorithm().as_str());
        writer.key("name").str(&self.name);
        writer.key("sign").bytes(self.signing.as_bytes());
        writer.key("relay").str(&self.relay);
        writer.key("trans").bytes(self.transport.as_bytes());
        writer.key("attest").bytes(self.attestation.as_bytes());
        writer.finish()
    }

    /// Reads canonical bytes, refusing anything else.
    ///
    /// # Errors
    ///
    /// When the bytes are not exactly one canonical payload, or a field is
    /// outside its bound. Nothing is repaired and no partial payload is
    /// returned.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > limits::MAX_PAYLOAD_SIZE {
            return Err(Error::TooLong {
                field: "payload",
                len: input.len(),
                limit: limits::MAX_PAYLOAD_SIZE,
            });
        }
        let mut reader = Reader::new(input);
        let mut map = reader.map(JOINING_SCHEMA)?;

        let algorithm = Algorithm::parse(map.key("alg")?.str(16, "algorithm")?)?;
        let name = map.key("name")?.str(limits::MAX_PROPOSED_NAME_LEN, "proposed name")?.to_owned();
        let signing = PublicKey::new(
            algorithm,
            map.key("sign")?.bytes(algorithm.public_key_len(), "signing key")?.to_vec(),
        )?;
        let relay = map.key("relay")?.str(limits::MAX_RELAY_LEN, "relay address")?.to_owned();
        let transport = PublicKey::new(
            Algorithm::Ed25519,
            map.key("trans")?.bytes(Algorithm::Ed25519.public_key_len(), "transport key")?.to_vec(),
        )?;
        let attestation = PublicKey::new(
            Algorithm::Ed25519,
            map.key("attest")?
                .bytes(Algorithm::Ed25519.public_key_len(), "attestation key")?
                .to_vec(),
        )?;

        map.finish()?;
        reader.finish()?;
        Self::new(signing, transport, attestation, name, relay)
    }

    /// The form a person copies.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::from(TEXT_PREFIX);
        out.push_str(&roster::hex::encode(&self.encode()));
        out
    }

    /// Reads the form a person copies.
    ///
    /// Surrounding whitespace is ignored, because a person copying from a
    /// terminal picks some up and that is not a reason to refuse them.
    ///
    /// # Errors
    ///
    /// When the prefix is absent, the body is not hex, or the bytes are not a
    /// payload.
    pub fn from_text(text: &str) -> Result<Self> {
        let trimmed = text.trim();
        let body = trimmed
            .strip_prefix(TEXT_PREFIX)
            .ok_or(Error::Malformed("it does not begin with peerfectly-join-v1:"))?;
        let bytes = roster::hex::decode(body.trim())
            .ok_or(Error::Malformed("the part after the prefix is not hexadecimal"))?;
        Self::decode(&bytes)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use identity::NodeIdentity;
    use roster::cbor::is_canonical_schema;

    use super::*;

    fn payload() -> Joining {
        let identity = NodeIdentity::generate().expect("generates");
        Joining::of(&identity, "laptop", "https://relay.example:443").expect("within bounds")
    }

    #[test]
    fn the_schema_is_in_canonical_key_order() {
        assert!(is_canonical_schema(JOINING_SCHEMA), "{JOINING_SCHEMA:?}");
        assert_eq!(JOINING_SCHEMA, &["alg", "name", "sign", "relay", "trans", "attest"]);
    }

    #[test]
    fn a_payload_round_trips_through_its_bytes() {
        let original = payload();
        let recovered = Joining::decode(&original.encode()).expect("decodes");
        assert_eq!(recovered, original);
    }

    /// One payload, one byte sequence. Two spellings of the same thing is how
    /// two implementations come to disagree about what was presented.
    #[test]
    fn re_encoding_is_byte_identical() {
        let original = payload();
        let bytes = original.encode();
        assert_eq!(Joining::decode(&bytes).expect("decodes").encode(), bytes);
    }

    /// The form a person copies carries the same bytes as the form a camera
    /// reads, or the two would be different payloads wearing one name.
    #[test]
    fn a_payload_round_trips_through_its_text_form() {
        let original = payload();
        let recovered = Joining::from_text(&original.to_text()).expect("decodes");
        assert_eq!(recovered, original);
        assert_eq!(recovered.encode(), original.encode());
    }

    #[test]
    fn text_survives_the_whitespace_a_terminal_adds() {
        let original = payload();
        let padded = format!("  {}\n", original.to_text());
        assert_eq!(Joining::from_text(&padded).expect("decodes"), original);
    }

    #[test]
    fn text_without_the_prefix_is_refused() {
        let original = payload();
        let body = original.to_text().replace(TEXT_PREFIX, "");
        assert!(matches!(Joining::from_text(&body), Err(Error::Malformed(_))));
    }

    /// A payload names what is asking. What it is permitted to be is decided by
    /// whoever admits it, so there is nowhere here to ask for a role.
    #[test]
    fn a_payload_cannot_ask_for_a_role() {
        let bytes = payload().encode();
        let text = String::from_utf8_lossy(&bytes);
        for forbidden in ["role", "admin", "founder", "capab"] {
            assert!(!text.contains(forbidden), "a payload must not carry `{forbidden}`");
        }
        assert_eq!(JOINING_SCHEMA.len(), 6, "six fields, and none of them a role");
    }

    /// Refused, never repaired. A changed byte either makes the payload
    /// undecodable or makes it a *different* payload — what must never happen is
    /// the decoder quietly recovering the original from bytes that are not it,
    /// because then a person could be shown one thing and admit another.
    #[test]
    fn no_single_byte_change_decodes_back_to_the_original() {
        let original = payload();
        let bytes = original.encode();

        for index in 0..bytes.len() {
            let mut altered = bytes.clone();
            let Some(byte) = altered.get_mut(index) else { continue };
            *byte = byte.wrapping_add(1);

            if let Ok(decoded) = Joining::decode(&altered) {
                assert_ne!(
                    decoded, original,
                    "byte {index} changed and the payload decoded back to the original"
                );
            }
        }
    }

    /// A payload that stops early is refused rather than read as far as it
    /// goes. A partially read payload would name a device nobody checked.
    #[test]
    fn a_truncated_payload_is_refused() {
        let bytes = payload().encode();
        for cut in 0..bytes.len() {
            let Some(short) = bytes.get(..cut) else { continue };
            assert!(Joining::decode(short).is_err(), "a payload cut at {cut} bytes was accepted");
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = payload().encode();
        bytes.push(0);
        assert!(Joining::decode(&bytes).is_err());
    }

    #[test]
    fn an_empty_name_or_relay_is_refused() {
        let identity = NodeIdentity::generate().expect("generates");
        assert!(matches!(
            Joining::of(&identity, "", "https://relay.example"),
            Err(Error::Empty("proposed name"))
        ));
        assert!(matches!(Joining::of(&identity, "laptop", ""), Err(Error::Empty("relay address"))));
    }

    #[test]
    fn an_oversized_name_or_relay_is_refused() {
        let identity = NodeIdentity::generate().expect("generates");
        let long_name = "n".repeat(limits::MAX_PROPOSED_NAME_LEN.saturating_add(1));
        let long_relay = "r".repeat(limits::MAX_RELAY_LEN.saturating_add(1));

        assert!(matches!(
            Joining::of(&identity, long_name, "https://relay.example"),
            Err(Error::TooLong { field: "proposed name", .. })
        ));
        assert!(matches!(
            Joining::of(&identity, "laptop", long_relay),
            Err(Error::TooLong { field: "relay address", .. })
        ));
    }

    /// A payload declares its own size bound before anything is read from it.
    #[test]
    fn an_oversized_payload_is_refused_before_it_is_parsed() {
        let huge = vec![0u8; limits::MAX_PAYLOAD_SIZE.saturating_add(1)];
        assert!(matches!(Joining::decode(&huge), Err(Error::TooLong { field: "payload", .. })));
    }
}

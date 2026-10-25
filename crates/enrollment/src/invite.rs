//! What an admin hands a device so that it can join.
//!
//! # It opens a door, once
//!
//! An invite carries the network's relay, the network's id and a secret. The
//! device that holds it waits at a rendezvous key derived from the secret; the
//! admin that issued it derives the same key and dials it. Nobody else knows
//! where to find the device, and the admin decides — before any request exists —
//! that one device may come in.
//!
//! It carries no name, role, mode or groups: those stay on the admin's device,
//! in the invite's local record. A person copying an invite carries a key to
//! a door, not a description of who walks through it.
//!
//! # Encoding
//!
//! The roster's canonical CBOR, as everything here: definite lengths, minimal
//! integers, length-first map keys, every field exactly once, no trailing
//! bytes, and rejection rather than repair. The text form is that, in
//! hexadecimal, after a prefix that is also its version; a scannable code
//! carries the text.

use roster::cbor::{Reader, Writer};
use roster::id::NetworkId;

use crate::error::{Error, Result};
use crate::limits;

/// The text form's prefix, which is also its version.
pub const TEXT_PREFIX: &str = "peerfectly-invite-v1:";

/// Field names of an invite, in canonical order.
pub const INVITE_SCHEMA: &[&str] = &["net", "relay", "secret"];

/// How many bytes of secret an invite carries.
pub const SECRET_LEN: usize = 16;

/// The context the rendezvous identity is derived under.
const RENDEZVOUS_CONTEXT: &str = "peerfectly invite rendezvous v1";

/// What an admin hands a device so that it can join.
#[derive(Clone, PartialEq, Eq)]
pub struct Invite {
    /// The network's relay, as `key@host:port`: where the device waits.
    pub relay: String,
    /// The network the device is invited into, and the only one it accepts.
    pub network: NetworkId,
    /// The secret both sides derive the rendezvous from.
    pub secret: [u8; SECRET_LEN],
}

impl core::fmt::Debug for Invite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The secret is the invite: not something to leave in a log.
        f.debug_struct("Invite")
            .field("relay", &self.relay)
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl Invite {
    /// An invite with this secret, checking its bounds.
    ///
    /// # Errors
    ///
    /// When the relay is empty or longer than its bound.
    pub fn new(
        relay: impl Into<String>,
        network: NetworkId,
        secret: [u8; SECRET_LEN],
    ) -> Result<Self> {
        let relay = relay.into();
        if relay.is_empty() {
            return Err(Error::Malformed("an invite names no relay"));
        }
        if relay.len() > limits::MAX_RELAY_LEN {
            return Err(Error::Malformed("the relay is longer than a relay may be"));
        }
        Ok(Self { relay, network, secret })
    }

    /// A new invite into `network` at `relay`, with a fresh random secret.
    ///
    /// # Errors
    ///
    /// As [`Self::new`], and when no randomness can be had.
    pub fn issue(relay: impl Into<String>, network: NetworkId) -> Result<Self> {
        let mut secret = [0u8; SECRET_LEN];
        getrandom::fill(&mut secret).map_err(|_| Error::Malformed("no randomness for a secret"))?;
        Self::new(relay, network, secret)
    }

    /// The seed of the rendezvous identity: the key the invited device waits
    /// under, and the admin's device dials. Bound to the network as well as the
    /// secret, so one secret cannot meet in two networks.
    #[must_use]
    pub fn rendezvous_seed(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(RENDEZVOUS_CONTEXT);
        hasher.update(self.network.as_bytes());
        hasher.update(&self.secret);
        *hasher.finalize().as_bytes()
    }

    /// Its canonical bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.map(3);
        writer.key("net").bytes(self.network.as_bytes());
        writer.key("relay").str(&self.relay);
        writer.key("secret").bytes(&self.secret);
        writer.finish()
    }

    /// Reads an invite, refusing anything not canonical.
    ///
    /// # Errors
    ///
    /// When the bytes are not a canonical invite within its bounds.
    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(input);
        let mut map = reader.map(INVITE_SCHEMA).map_err(|_| Error::Malformed("not an invite"))?;
        let network = map
            .key("net")
            .and_then(|value| value.fixed_bytes(32))
            .map_err(|_| Error::Malformed("not an invite"))?;
        let mut network_bytes = [0u8; 32];
        network_bytes.copy_from_slice(network);
        let relay = map
            .key("relay")
            .and_then(|value| value.str(limits::MAX_RELAY_LEN, "relay length"))
            .map_err(|_| Error::Malformed("not an invite"))?
            .to_owned();
        let secret = map
            .key("secret")
            .and_then(|value| value.fixed_bytes(SECRET_LEN))
            .map_err(|_| Error::Malformed("not an invite"))?;
        let mut secret_bytes = [0u8; SECRET_LEN];
        secret_bytes.copy_from_slice(secret);
        map.finish().map_err(|_| Error::Malformed("not an invite"))?;
        reader.finish().map_err(|_| Error::Malformed("not an invite"))?;
        Self::new(relay, NetworkId::from_bytes(network_bytes), secret_bytes)
    }

    /// The form a person copies, and a scannable code carries.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::from(TEXT_PREFIX);
        out.push_str(&roster::hex::encode(&self.encode()));
        out
    }

    /// Reads the form a person copies. Surrounding whitespace is ignored.
    ///
    /// # Errors
    ///
    /// When the prefix is absent, the body is not hexadecimal, or the bytes
    /// are not an invite.
    pub fn from_text(text: &str) -> Result<Self> {
        let body = text
            .trim()
            .strip_prefix(TEXT_PREFIX)
            .ok_or(Error::Malformed("it does not begin with peerfectly-invite-v1:"))?;
        let bytes = roster::hex::decode(body.trim())
            .ok_or(Error::Malformed("the part after the prefix is not hexadecimal"))?;
        Self::decode(&bytes)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use roster::cbor::is_canonical_schema;

    use super::*;

    fn invite() -> Invite {
        Invite::new(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a@relay.example:4433",
            NetworkId::from_bytes([7; 32]),
            [9; SECRET_LEN],
        )
        .unwrap()
    }

    #[test]
    fn the_schema_is_canonical() {
        assert!(is_canonical_schema(INVITE_SCHEMA));
    }

    #[test]
    fn an_invite_round_trips_through_its_bytes_and_its_text() {
        let original = invite();
        assert_eq!(Invite::decode(&original.encode()).unwrap(), original);
        assert_eq!(Invite::from_text(&original.to_text()).unwrap(), original);
        assert_eq!(Invite::from_text(&format!("  {}\n", original.to_text())).unwrap(), original);
    }

    #[test]
    fn it_carries_the_relay_the_network_and_the_secret_and_nothing_else() {
        let bytes = invite().encode();
        assert!(bytes.len() < 160, "small enough for a code: {} bytes", bytes.len());
        for absent in [&b"name"[..], b"role", b"mode", b"groups"] {
            assert!(!bytes.windows(absent.len()).any(|window| window == absent));
        }
    }

    #[test]
    fn a_corrupted_invite_is_refused() {
        let text = invite().to_text();
        assert!(
            Invite::from_text(&text.replace("invite-v1", "invite-v2")).is_err(),
            "another version"
        );
        assert!(Invite::from_text(&text[..text.len() - 2]).is_err(), "cut short");
        assert!(Invite::from_text(&format!("{text}00")).is_err(), "something trailing");
        assert!(Invite::from_text(&text.replace(TEXT_PREFIX, "")).is_err(), "no prefix");
        let mut bytes = invite().encode();
        if let Some(first) = bytes.first_mut() {
            *first = 0xa2;
        }
        assert!(Invite::decode(&bytes).is_err(), "a map of the wrong size");
        assert!(Invite::new("", NetworkId::from_bytes([7; 32]), [0; SECRET_LEN]).is_err());
    }

    #[test]
    fn two_invites_meet_at_different_keys_and_one_secret_at_one() {
        let one = Invite::issue("k@relay:1", NetworkId::from_bytes([7; 32])).unwrap();
        let two = Invite::issue("k@relay:1", NetworkId::from_bytes([7; 32])).unwrap();
        assert_ne!(one.secret, two.secret);
        assert_ne!(one.rendezvous_seed(), two.rendezvous_seed());
        let read = Invite::from_text(&one.to_text()).unwrap();
        assert_eq!(read.rendezvous_seed(), one.rendezvous_seed(), "both sides derive the same");
        let elsewhere = Invite { network: NetworkId::from_bytes([8; 32]), ..one.clone() };
        assert_ne!(elsewhere.rendezvous_seed(), one.rendezvous_seed(), "bound to the network");
    }

    #[test]
    fn the_secret_is_not_in_its_debug_form() {
        assert!(!format!("{:?}", invite()).contains("secret"));
    }
}

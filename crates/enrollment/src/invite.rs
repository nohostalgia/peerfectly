//! What an admin hands a device so that it can join.
//!
//! # It opens a door, once
//!
//! An invite carries the network's relay, the network's id, its IPv4 block, a
//! secret and an anchor. The
//! device that holds it waits at a rendezvous key derived from the secret; the
//! admin that issued it derives the same key and dials it. Nobody else knows
//! where to find the device, and the admin decides — before any request exists —
//! that one device may come in.
//!
//! The block is there so the joining device can say, before it asks, where the
//! network's addresses would coincide with its other networks or the subnets it
//! is on (`scalable-membership` 19.5). Nothing signs it: an invite that lied
//! about it misleads only that warning, and the block the device holds is the
//! one the delivered roster says.
//!
//! The suffix is there for the same reason, about names: a device holding a
//! network whose names overlap it refuses the join before anything is sent,
//! rather than after an admin approved it (offline-founder design §21). It is
//! the issuer's word too; the delivered roster's suffix is judged again.
//!
//! It carries no name, role, mode or groups: those stay on the admin's device,
//! in the invite's local record. A person copying an invite carries a key to
//! a door, not a description of who walks through it.
//!
//! # The anchor
//!
//! The id of the key that vouches for the network the device is given: the
//! inviting admin's attestation key, or the founder's signing key for an invite
//! opened with the founder's words. The device adopts a network only with a
//! root that key signed, over a state that admits it (`adopt::adopt_anchored`).
//!
//! The secret alone is a bearer token. Somebody who learned it could otherwise
//! hand the device a network of their own making under the invited network's
//! id: once a network's history is compacted past its founding, the state it
//! rests on names its own keys and nothing ties it to the id.
//!
//! # Encoding
//!
//! The roster's canonical CBOR, as everything here: definite lengths, minimal
//! integers, length-first map keys, every field exactly once, no trailing
//! bytes, and rejection rather than repair. The text form is that, in base32
//! ([`crate::base32`]), after a prefix that is also its version; a scannable
//! code carries the text.

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;

use roster::cbor::{Reader, Writer};
use roster::id::{KeyId, NetworkId};
use roster::types::{IPV4_RANGE_LEN, Ipv4Range};

use crate::error::{Error, Result};
use crate::limits;

/// The text form's prefix, which is also its version.
pub const TEXT_PREFIX: &str = "peerfectly-invite-v3:";

/// What every version's prefix begins with: an invite of another version is
/// told apart from text that is no invite at all.
const ANY_VERSION: &str = "peerfectly-invite-";

/// Field names of an invite, in canonical order.
pub const INVITE_SCHEMA: &[&str] = &["net", "block", "relay", "anchor", "secret", "suffix"];

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
    /// The network's IPv4 block when the invite was issued, as its admin said.
    pub block: Ipv4Range,
    /// The secret both sides derive the rendezvous from.
    pub secret: [u8; SECRET_LEN],
    /// The key whose root the device must be given with the network.
    pub anchor: KeyId,
    /// The network's suffix when the invite was issued, as its admin said;
    /// empty where it was not said.
    pub suffix: String,
}

impl core::fmt::Debug for Invite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The secret is the invite: not something to leave in a log.
        f.debug_struct("Invite")
            .field("relay", &self.relay)
            .field("network", &self.network)
            .field("block", &self.block)
            .field("anchor", &self.anchor)
            .field("suffix", &self.suffix)
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
        block: Ipv4Range,
        secret: [u8; SECRET_LEN],
        anchor: KeyId,
    ) -> Result<Self> {
        let relay = relay.into();
        if relay.is_empty() {
            return Err(Error::Malformed("an invite names no relay"));
        }
        if relay.len() > limits::MAX_RELAY_LEN {
            return Err(Error::Malformed("the relay is longer than a relay may be"));
        }
        Ok(Self { relay, network, block, secret, anchor, suffix: String::new() })
    }

    /// The same invite, saying the network's suffix.
    ///
    /// # Errors
    ///
    /// When the suffix is longer than a suffix may be.
    pub fn with_suffix(mut self, suffix: impl Into<String>) -> Result<Self> {
        let suffix = suffix.into();
        if suffix.len() > roster::limits::MAX_SUFFIX_LEN {
            return Err(Error::Malformed("the suffix is longer than a suffix may be"));
        }
        self.suffix = suffix;
        Ok(self)
    }

    /// A new invite into `network` at `relay`, anchored to `anchor`, with a
    /// fresh random secret.
    ///
    /// # Errors
    ///
    /// As [`Self::new`], and when no randomness can be had.
    #[cfg(feature = "std")]
    pub fn issue(
        relay: impl Into<String>,
        network: NetworkId,
        block: Ipv4Range,
        anchor: KeyId,
    ) -> Result<Self> {
        let mut secret = [0u8; SECRET_LEN];
        getrandom::fill(&mut secret).map_err(|_| Error::Malformed("no randomness for a secret"))?;
        Self::new(relay, network, block, secret, anchor)
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
        writer.map(6);
        writer.key("net").bytes(self.network.as_bytes());
        writer.key("block").bytes(&self.block.to_bytes());
        writer.key("relay").str(&self.relay);
        writer.key("anchor").bytes(self.anchor.as_bytes());
        writer.key("secret").bytes(&self.secret);
        writer.key("suffix").str(&self.suffix);
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
        let block = map
            .key("block")
            .and_then(|value| value.fixed_bytes(IPV4_RANGE_LEN))
            .and_then(Ipv4Range::from_bytes)
            .map_err(|_| Error::Malformed("not an invite"))?;
        let relay = map
            .key("relay")
            .and_then(|value| value.str(limits::MAX_RELAY_LEN, "relay length"))
            .map_err(|_| Error::Malformed("not an invite"))?
            .to_owned();
        let anchor = map
            .key("anchor")
            .and_then(|value| value.fixed_bytes(32))
            .map_err(|_| Error::Malformed("not an invite"))?;
        let mut anchor_bytes = [0u8; 32];
        anchor_bytes.copy_from_slice(anchor);
        let secret = map
            .key("secret")
            .and_then(|value| value.fixed_bytes(SECRET_LEN))
            .map_err(|_| Error::Malformed("not an invite"))?;
        let mut secret_bytes = [0u8; SECRET_LEN];
        secret_bytes.copy_from_slice(secret);
        let suffix = map
            .key("suffix")
            .and_then(|value| value.str(roster::limits::MAX_SUFFIX_LEN, "suffix length"))
            .map_err(|_| Error::Malformed("not an invite"))?
            .to_owned();
        map.finish().map_err(|_| Error::Malformed("not an invite"))?;
        reader.finish().map_err(|_| Error::Malformed("not an invite"))?;
        Self::new(
            relay,
            NetworkId::from_bytes(network_bytes),
            block,
            secret_bytes,
            KeyId::from_bytes(anchor_bytes),
        )?
        .with_suffix(suffix)
    }

    /// The form a person copies, and a scannable code carries.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::from(TEXT_PREFIX);
        out.push_str(&crate::base32::encode(&self.encode()));
        out
    }

    /// Reads the form a person copies. Surrounding whitespace is ignored.
    ///
    /// # Errors
    ///
    /// When the prefix is absent or of another version, the body is not base32,
    /// or the bytes are not an invite.
    pub fn from_text(text: &str) -> Result<Self> {
        let text = text.trim();
        let Some(body) = text.strip_prefix(TEXT_PREFIX) else {
            return Err(Error::Malformed(if text.starts_with(ANY_VERSION) {
                "it is an invite of an earlier version: ask the network's admin for a new one"
            } else {
                "it does not begin with peerfectly-invite-v3:"
            }));
        };
        let bytes = crate::base32::decode(body.trim())
            .ok_or(Error::Malformed("the part after the prefix is not base32"))?;
        Self::decode(&bytes)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use roster::cbor::is_canonical_schema;

    use super::*;

    fn anchor() -> KeyId {
        KeyId::from_bytes([3; 32])
    }

    fn invite() -> Invite {
        Invite::new(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a@relay.example:4433",
            NetworkId::from_bytes([7; 32]),
            "100.83.0.0/16".parse().unwrap(),
            [9; SECRET_LEN],
            anchor(),
        )
        .unwrap()
        .with_suffix("home.internal")
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
        assert_eq!(original.anchor, anchor(), "the anchor with it");
        assert_eq!(original.suffix, "home.internal", "and the suffix");
    }

    #[test]
    fn it_carries_the_relay_the_network_the_block_the_anchor_and_the_secret_and_nothing_else() {
        let bytes = invite().encode();
        // The anchor adds forty-one bytes to the 166 before it, the suffix
        // seven and its own length.
        assert!(bytes.len() < 230, "small enough for a code: {} bytes", bytes.len());
        // And base32 carries them in about as many characters as hexadecimal
        // carried the invite without the anchor: 332 after the prefix then.
        let text = invite().to_text();
        assert!(text.len() <= TEXT_PREFIX.len() + 370, "{} characters", text.len());
        for absent in [&b"name"[..], b"role", b"mode", b"groups"] {
            assert!(!bytes.windows(absent.len()).any(|window| window == absent));
        }
    }

    #[test]
    fn a_corrupted_invite_is_refused() {
        let text = invite().to_text();
        assert!(
            Invite::from_text(&text.replace("invite-v3", "invite-v2")).is_err(),
            "another version"
        );
        assert!(Invite::from_text(&text[..text.len() - 2]).is_err(), "cut short");
        assert!(Invite::from_text(&format!("{text}aa")).is_err(), "something trailing");
        assert!(Invite::from_text(&text.replace(TEXT_PREFIX, "")).is_err(), "no prefix");
        let mut bytes = invite().encode();
        if let Some(first) = bytes.first_mut() {
            *first = 0xa4;
        }
        assert!(Invite::decode(&bytes).is_err(), "a map of the wrong size");
        assert!(
            Invite::new(
                "",
                NetworkId::from_bytes([7; 32]),
                Ipv4Range::DEFAULT,
                [0; SECRET_LEN],
                anchor()
            )
            .is_err()
        );
    }

    /// An invite a person still holds from before is not read as gibberish:
    /// they are told to ask for a new one.
    #[test]
    fn an_invite_of_an_earlier_version_says_so() {
        let refused = Invite::from_text("peerfectly-invite-v2:a40363").unwrap_err();
        assert!(refused.to_string().contains("earlier version"), "{refused}");
    }

    #[test]
    fn two_invites_meet_at_different_keys_and_one_secret_at_one() {
        let network = NetworkId::from_bytes([7; 32]);
        let one = Invite::issue("k@relay:1", network, Ipv4Range::DEFAULT, anchor()).unwrap();
        let two = Invite::issue("k@relay:1", network, Ipv4Range::DEFAULT, anchor()).unwrap();
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

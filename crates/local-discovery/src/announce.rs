//! What goes on the wire, and what a stranger sees instead.
//!
//! # The payload is a rendezvous record, under a different context
//!
//! §8's announcement is a public key plus an endpoint, signed — exactly what
//! [`rendezvous::Record`] carries. Copying the struct would mean two canonical
//! formats for one thing, drifting apart in the way this project has already had
//! to correct once.
//!
//! **The signing context differs, and that is not cosmetic.** Signed under
//! [`DOMAIN_TAG`], never the rendezvous tag. Without the separation, an
//! announcement *is* a valid rendezvous record: anyone sharing a café network
//! could capture one and publish it, and because the device itself signed it at
//! a sequence above whatever it last published globally, it would **replace that
//! device's published addresses with LAN-only ones**. Peers elsewhere would
//! fetch `192.168.x` and fail until the device published again — reachability
//! destroyed by an observer holding no key at all.
//!
//! Two tags make that impossible in both directions.
//!
//! # The wire form is obfuscated, and that is all it is
//!
//! The signed announcement is encrypted under a key derived from the network id,
//! so an observer on the same wifi sees random-looking bytes rather than a
//! public key and a presence beacon. For a product sold on sovereignty,
//! broadcasting a stable device identity to every café is a poor default.
//!
//! **This is obfuscation, not confidentiality.** The network id is not a secret.
//! Every member knows it, and so does every *former* member whose device was
//! revoked. It defends against an observer who never held the roster, and
//! against nobody else. It must never be described as confidentiality, and
//! successful decryption must never be treated as authentication — see
//! [`open`].
//!
//! **There is no plaintext discriminator.** The obvious optimisation — a
//! per-network tag in the clear, so a listener skips foreign packets without
//! attempting decryption — would hand an observer a stable identifier for the
//! network and let them track its presence over time without reading anything.
//! That is most of what the encryption is for. A listener attempts decryption
//! instead, which on a dedicated port costs one AEAD failure per foreign packet.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rendezvous::Record;
use roster::id::NetworkId;
use roster::limits::SIGNATURE_LEN;
use roster::sign::Signer;

use crate::error::{Error, Result};
use crate::limits;

/// The version tag every announcement signature is bound to.
///
/// The fifth signing context in the system, after `roster/v1`,
/// `roster-snapshot/v1`, `transport-session/v1` and `rendezvous-record/v1`. It
/// exists so an announcement and a rendezvous record cannot be exchanged; see
/// the module documentation for what that prevents.
pub const DOMAIN_TAG: &str = "local-announce/v1";

/// The context string the packet key is derived under.
///
/// Distinct from the signing tag, so the value used to encrypt is not the value
/// used to sign even though both descend from the network id.
const KEY_CONTEXT: &str = "peerfectly local-announce v1 packet key";

/// Builds the byte string an announcement signature covers.
///
/// Framed exactly as roster's envelopes are: each component preceded by its
/// length as a big-endian `u16`, so no two component tuples concatenate to the
/// same bytes.
#[must_use]
pub fn signing_input(network: &NetworkId, record_bytes: &[u8]) -> Vec<u8> {
    let tag = DOMAIN_TAG.as_bytes();
    let mut out = Vec::with_capacity(
        tag.len().saturating_add(32).saturating_add(record_bytes.len()).saturating_add(6),
    );
    push_framed(&mut out, tag);
    push_framed(&mut out, network.as_bytes());
    push_framed(&mut out, record_bytes);
    out
}

/// Appends a component preceded by its big-endian `u16` length.
fn push_framed(out: &mut Vec<u8>, component: &[u8]) {
    let len = u16::try_from(component.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(component);
}

/// The key a network's packets are encrypted under.
///
/// Derived rather than stored, so there is no key material to manage and nothing
/// to lose. Derived from a value that is not secret, which is the whole limit of
/// this protection.
fn packet_key(network: &NetworkId) -> Key {
    let derived = blake3::derive_key(KEY_CONTEXT, network.as_bytes());
    Key::from(derived)
}

/// An announcement, signed and ready to be sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    /// The exact bytes that were signed, kept rather than re-encoded so
    /// verification is over what arrived.
    bytes: Vec<u8>,
    /// The decoded record.
    record: Record,
    /// The signature over [`signing_input`] of `bytes`.
    signature: [u8; SIGNATURE_LEN],
}

impl Announcement {
    /// Signs a record as an announcement.
    pub fn sign(record: Record, signer: &dyn Signer) -> Result<Self> {
        let bytes = record.encode();
        let input = signing_input(&record.network, &bytes);
        let raw = signer.sign(&input).map_err(|_| Error::SignatureInvalid)?;
        let signature: [u8; SIGNATURE_LEN] = raw.try_into().map_err(|_| Error::SignatureInvalid)?;
        Ok(Self { bytes, record, signature })
    }

    /// The record announced.
    #[must_use]
    pub const fn record(&self) -> &Record {
        &self.record
    }

    /// The signed form, before it is sealed.
    #[must_use]
    fn to_signed_bytes(&self) -> Vec<u8> {
        let mut out = self.bytes.clone();
        out.extend_from_slice(&self.signature);
        out
    }
}

/// Seals an announcement into the packet that goes on the wire.
///
/// `nonce` is supplied so a test can be deterministic; production callers use
/// [`seal`], which draws one from the system.
pub fn seal_with_nonce(
    announcement: &Announcement,
    network: &NetworkId,
    nonce: [u8; limits::NONCE_LEN],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(&packet_key(network));
    let sealed = cipher
        .encrypt(&Nonce::from(nonce), announcement.to_signed_bytes().as_slice())
        .map_err(|_| Error::NotAnAnnouncement)?;

    let mut packet = Vec::with_capacity(nonce.len().saturating_add(sealed.len()));
    // The nonce is the only thing in the clear, and it is random per packet, so
    // it identifies nothing across packets.
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&sealed);

    if packet.len() > limits::MAX_PACKET_SIZE {
        return Err(Error::NotAnAnnouncement);
    }
    Ok(packet)
}

/// Seals an announcement with a fresh random nonce.
pub fn seal(announcement: &Announcement, network: &NetworkId) -> Result<Vec<u8>> {
    let mut nonce = [0u8; limits::NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| Error::NotAnAnnouncement)?;
    seal_with_nonce(announcement, network, nonce)
}

/// Opens a packet: decrypt, decode, then **verify**.
///
/// The order matters and so does the last step. A packet that decrypts proves
/// only that its sender knew the network id — a value every member and every
/// former member knows. Decryption is **never** authentication. Only the
/// signature is evidence, and even it proves key possession rather than
/// membership: §8 is explicit that a discovered device is never proof of
/// anything.
pub fn open(packet: &[u8], network: &NetworkId) -> Result<Announcement> {
    if packet.len() > limits::MAX_PACKET_SIZE {
        return Err(Error::NotAnAnnouncement);
    }
    let split = packet.len().checked_sub(limits::NONCE_LEN);
    let Some(_) = split.filter(|_| packet.len() > limits::NONCE_LEN) else {
        return Err(Error::NotAnAnnouncement);
    };
    let (nonce, sealed) = packet.split_at(limits::NONCE_LEN);

    let cipher = ChaCha20Poly1305::new(&packet_key(network));
    // Failure here is the ordinary case: the port is shared with every other
    // network in range, and this says only "not ours".
    let nonce: [u8; limits::NONCE_LEN] = nonce.try_into().map_err(|_| Error::NotAnAnnouncement)?;
    let plain =
        cipher.decrypt(&Nonce::from(nonce), sealed).map_err(|_| Error::NotForThisNetwork)?;

    let body_len = plain.len().checked_sub(SIGNATURE_LEN).ok_or(Error::NotAnAnnouncement)?;
    let (body, tail) = plain.split_at(body_len);
    let mut signature = [0u8; SIGNATURE_LEN];
    signature.copy_from_slice(tail);

    let record = Record::decode(body).map_err(|_| Error::Malformed(roster::Error::BodySchema))?;
    if record.network != *network {
        return Err(Error::NotForThisNetwork);
    }

    // Verified over the bytes as received, never a re-encoding: a re-encoding
    // would verify what this implementation understood rather than what the
    // signer signed.
    let expected = signing_input(&record.network, body);
    record.key.verify(&expected, &signature).map_err(|_| Error::SignatureInvalid)?;

    Ok(Announcement { bytes: body.to_vec(), record, signature })
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test reports a failed expectation by panicking")]
mod tests {
    use identity::PrivateKey;
    use roster::types::Algorithm;

    use super::*;

    fn network() -> NetworkId {
        NetworkId::from_bytes([5; 32])
    }

    fn device() -> PrivateKey {
        PrivateKey::generate(Algorithm::Ed25519).expect("generates")
    }

    fn announcement(device: &PrivateKey, net: NetworkId, sequence: u64) -> Announcement {
        let record = Record::new(
            device.public_key(),
            net,
            sequence,
            vec!["ip:192.168.1.5:41641".to_owned()],
        )
        .expect("within bounds");
        Announcement::sign(record, device.signer()).expect("signs")
    }

    /// The fifth signing context, distinct from every other. Without this an
    /// announcement is a valid rendezvous record.
    /// One network's announcement key never opens its rendezvous records: the
    /// two seals are derived under different contexts from the same id.
    #[test]
    fn the_packet_key_is_not_the_rendezvous_seal() {
        assert_ne!(KEY_CONTEXT, rendezvous::SEAL_CONTEXT);
    }

    #[test]
    fn the_tag_is_distinct_from_every_other_context() {
        for other in
            ["roster/v1", "roster-snapshot/v1", "transport-session/v1", "rendezvous-record/v1"]
        {
            assert_ne!(DOMAIN_TAG, other);
        }
        assert_eq!(DOMAIN_TAG, "local-announce/v1");
    }

    /// The attack the separation prevents: an announcement captured on a café
    /// network and published as a rendezvous record would replace a device's
    /// global addresses with LAN-only ones it signed itself.
    #[test]
    fn an_announcement_does_not_verify_as_a_rendezvous_record() {
        let device = device();
        let net = network();
        let record =
            Record::new(device.public_key(), net, 1, vec!["ip:192.168.1.5:41641".to_owned()])
                .expect("within bounds");

        let announced = Announcement::sign(record.clone(), device.signer()).expect("signs");
        let mut as_rendezvous = announced.bytes.clone();
        as_rendezvous.extend_from_slice(&announced.signature);

        assert!(
            rendezvous::SignedRecord::decode_and_verify(&as_rendezvous).is_err(),
            "an announcement must not be publishable as a rendezvous record"
        );
    }

    #[test]
    fn a_rendezvous_record_does_not_verify_as_an_announcement() {
        let device = device();
        let net = network();
        let record =
            Record::new(device.public_key(), net, 1, vec!["ip:a".to_owned()]).expect("bounds");
        let signed = rendezvous::SignedRecord::sign(record, device.signer()).expect("signs");

        let sealed = {
            let cipher = ChaCha20Poly1305::new(&packet_key(&net));
            let nonce = [7u8; limits::NONCE_LEN];
            let body = cipher
                .encrypt(&Nonce::from(nonce), signed.to_bytes().as_slice())
                .expect("encrypts");
            let mut packet = nonce.to_vec();
            packet.extend_from_slice(&body);
            packet
        };

        // Since the rendezvous format's v2 a record no longer has an
        // announcement's shape at all, so it is refused on the schema before the
        // signature is reached. Either refusal is the property; accepting it is not.
        assert!(
            matches!(open(&sealed, &net), Err(Error::SignatureInvalid | Error::Malformed(_))),
            "{:?}",
            open(&sealed, &net)
        );
    }

    #[test]
    fn a_sealed_announcement_round_trips() {
        let device = device();
        let net = network();
        let announced = announcement(&device, net, 3);

        let packet = seal(&announced, &net).expect("seals");
        let opened = open(&packet, &net).expect("opens");

        assert_eq!(opened.record().sequence, 3);
        assert_eq!(opened.record().key.as_bytes(), device.public_key().as_bytes());
    }

    /// A stranger without the network id sees nothing usable.
    #[test]
    fn another_network_cannot_open_it() {
        let device = device();
        let net = network();
        let packet = seal(&announcement(&device, net, 1), &net).expect("seals");

        let elsewhere = NetworkId::from_bytes([200; 32]);
        assert_eq!(open(&packet, &elsewhere), Err(Error::NotForThisNetwork));
    }

    /// The announced key must not be readable from the packet by anyone who
    /// lacks the network id — that is the whole point of the obfuscation.
    #[test]
    fn the_announced_key_is_not_visible_in_the_packet() {
        let device = device();
        let net = network();
        let packet = seal(&announcement(&device, net, 1), &net).expect("seals");

        let key = device.public_key();
        assert!(
            !packet.windows(32).any(|window| window == key.as_bytes()),
            "the public key must not appear in the clear"
        );
    }

    /// No stable per-network field in the clear: a discriminator would let an
    /// observer track a network's presence without reading anything.
    #[test]
    fn nothing_stable_is_exposed_between_two_packets() {
        let device = device();
        let net = network();
        let first = seal(&announcement(&device, net, 1), &net).expect("seals");
        let second = seal(&announcement(&device, net, 2), &net).expect("seals");

        // The nonce is the only cleartext, and it differs per packet.
        assert_ne!(
            first.get(..limits::NONCE_LEN),
            second.get(..limits::NONCE_LEN),
            "the nonce must be fresh per packet"
        );

        // No run of bytes long enough to serve as a stable tag is shared at a
        // fixed position.
        let shared = first.iter().zip(second.iter()).take_while(|(a, b)| a == b).count();
        assert!(shared < 4, "{shared} leading bytes are identical between packets");
    }

    /// Decryption proves only that the sender knew a value every member and
    /// ex-member knows. It is never authentication.
    #[test]
    fn decryption_is_not_authentication() {
        let device = device();
        let net = network();
        let announced = announcement(&device, net, 1);

        // Sealed correctly, but the signature is corrupted inside.
        let mut signed = announced.to_signed_bytes();
        let last = signed.len().saturating_sub(1);
        if let Some(byte) = signed.get_mut(last) {
            *byte ^= 0xff;
        }
        let cipher = ChaCha20Poly1305::new(&packet_key(&net));
        let nonce = [1u8; limits::NONCE_LEN];
        let body = cipher.encrypt(&Nonce::from(nonce), signed.as_slice()).expect("encrypts");
        let mut packet = nonce.to_vec();
        packet.extend_from_slice(&body);

        assert_eq!(
            open(&packet, &net),
            Err(Error::SignatureInvalid),
            "decrypting must grant a packet nothing"
        );
    }

    #[test]
    fn noise_on_the_port_is_ordinary() {
        let net = network();
        for input in [b"".as_slice(), b"short".as_slice(), &[0u8; 64]] {
            let outcome = open(input, &net).expect_err("must not open");
            assert!(
                outcome.is_background_noise(),
                "arbitrary bytes are noise, not a fault: {outcome:?}"
            );
        }
    }

    #[test]
    fn an_oversized_packet_is_refused() {
        let net = network();
        let packet = vec![0u8; limits::MAX_PACKET_SIZE + 1];
        assert_eq!(open(&packet, &net), Err(Error::NotAnAnnouncement));
    }

    #[test]
    fn a_real_announcement_fits_the_packet_bound() {
        let device = device();
        let net = network();
        let record = Record::new(
            device.public_key(),
            net,
            u64::MAX,
            (0..limits::MAX_ADDRESSES_PER_PEER)
                .map(|i| format!("ip:192.168.100.{i}:41641"))
                .collect(),
        )
        .expect("within bounds");
        let announced = Announcement::sign(record, device.signer()).expect("signs");

        let packet = seal(&announced, &net).expect("a full announcement must still fit");
        assert!(packet.len() <= limits::MAX_PACKET_SIZE, "{} bytes", packet.len());
    }
}

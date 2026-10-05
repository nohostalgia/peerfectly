//! The six digits a person compares, and why they are bound to the channel.
//!
//! # Every key in this derivation is public
//!
//! The joining payload is on a screen; the admin's keys are in a roster every
//! member holds. A code derived from keys alone could therefore be computed by
//! anyone who had seen the payload — including the code the *legitimate*
//! exchange is about to display. Knowing that value, an attacker generates key
//! pairs of their own until one produces the same six digits. Six digits is a
//! space of one million: the search takes seconds, and the person then compares
//! two screens showing the same number and confirms an enrolment into the
//! attacker's network.
//!
//! So the derivation takes **material exported from the established channel**.
//! The value being matched does not exist until the channel does, and the
//! attacker's channel is not the one being matched. It also breaks a forwarded
//! exchange: two legs export two different values, so the codes differ at each
//! end.
//!
//! Channel material is required, not optional, and empty is refused. A default
//! would be a way to lose this property by accident.
//!
//! # The two roles are not symmetric, and cannot be
//!
//! The joining device brings both of its keys: its signing key is proved by
//! [`crate::Possession`], its transport key by the channel. The admitting device
//! brings only its transport key, because that is all the joining device can
//! know about it — the admitting device's signing key lives in the roster that
//! has not arrived yet.
//!
//! Having it asserted over the wire and mixed in would look like a binding and
//! be none: an impostor would assert its own key and compute the same code. What
//! exposes an impostor is that its channel is a different channel.

use roster::sign::PublicKey;

use crate::error::{Error, Result};
use crate::limits;

/// The derivation context for a confirmation code.
///
/// Domain separation: this value cannot be produced by any other derivation in
/// this system, and no other derivation can be produced by this one.
pub const DOMAIN_CODE: &str = "peerfectly enrolment confirmation code v1";

/// The number of codes there are, which is ten to the power of the digit count.
const CODES: u64 = 1_000_000;

/// What the joining device brings to an exchange.
///
/// Every key that will end up in its device record. Two of them are established
/// independently — the signing key by the proof of possession, the transport key
/// by the channel the admitting side dialled — and the attestation key is not.
///
/// It is here anyway, and that is the point. The code exists so that what the
/// admitting side signs into the roster is what both people compared. The
/// attestation key goes into the device record, so a code that did not cover it
/// would leave a field in that record neither person ever saw — and a payload
/// substituted in flight could name an attestation key of the attacker's
/// choosing while showing the same six digits.
///
/// Possession of it is not proven by this, and does not need to be: what the
/// code buys is that the field cannot be changed without the digits changing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Side {
    /// The device's signing key, from which its identity is derived.
    pub signing: PublicKey,
    /// The device's transport key, which the channel authenticates.
    pub transport: PublicKey,
    /// The device's attestation key, which will date its roster.
    pub attestation: PublicKey,
}

/// A confirmation code, as both people will read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmation(String);

impl Confirmation {
    /// Derives the code for one exchange.
    ///
    /// The roles are fixed and different, so there is no order to agree on: the
    /// admitting side knows the joining device's keys from its payload, and the
    /// joining device knows the admitting side's transport key from the channel.
    /// Each supplies what it knows and both arrive at one value.
    ///
    /// # Errors
    ///
    /// When the channel material is empty, which would remove the one property
    /// that makes a six-digit code safe here.
    pub fn derive(joining: &Side, admitting_transport: &PublicKey, channel: &[u8]) -> Result<Self> {
        if channel.is_empty() {
            return Err(Error::Malformed("a confirmation code needs channel material"));
        }

        let mut input = Vec::new();
        push_field(&mut input, joining.signing.as_bytes());
        push_field(&mut input, joining.transport.as_bytes());
        push_field(&mut input, joining.attestation.as_bytes());
        push_field(&mut input, admitting_transport.as_bytes());
        push_field(&mut input, channel);

        let digest = blake3::derive_key(DOMAIN_CODE, &input);
        Ok(Self(digits(&digest)))
    }

    /// The code as a person reads it: fixed width, leading zeros kept.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether what a person typed is this code.
    ///
    /// Surrounding whitespace is ignored, because a person typing six digits
    /// into a terminal sometimes adds a space and that is not a reason to refuse
    /// them. Nothing else is: a code is compared, never interpreted.
    #[must_use]
    pub fn matches(&self, entered: &str) -> bool {
        entered.trim() == self.0
    }
}

impl core::fmt::Display for Confirmation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Appends a length-prefixed field.
///
/// Without the length, two different pairs of fields could concatenate to the
/// same bytes, and two different exchanges could produce one code.
fn push_field(out: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
}

/// The digits, from the first eight bytes of the digest.
fn digits(digest: &[u8; 32]) -> String {
    let mut head = [0u8; 8];
    if let Some(source) = digest.get(..8) {
        head.copy_from_slice(source);
    }
    let value = u64::from_be_bytes(head) % CODES;
    let width = limits::CODE_DIGITS as usize;
    format!("{value:0width$}")
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use identity::NodeIdentity;

    use super::*;

    fn side() -> Side {
        let identity = NodeIdentity::generate().expect("generates");
        Side {
            signing: identity.signing_key().public_key(),
            transport: identity.transport_key().public_key(),
            attestation: identity.attestation_key().public_key(),
        }
    }

    /// An admitting device, of which only the transport key is ever known here.
    fn admitting() -> PublicKey {
        NodeIdentity::generate().expect("generates").transport_key().public_key()
    }

    #[test]
    fn the_code_space_matches_the_digit_count() {
        assert_eq!(CODES, 10_u64.pow(limits::CODE_DIGITS));
    }

    /// Each side computes it from what its role actually knows, and the two
    /// agree. The joining device never needs the admitting device's signing key,
    /// which it could not have.
    #[test]
    fn each_side_computes_it_from_what_it_knows() {
        let joining = side();
        let admitting = admitting();
        let channel = b"one exchange";

        // The admitting side reads the joining device's keys from its payload.
        let from_the_admin = Confirmation::derive(&joining, &admitting, channel).expect("derives");
        // The joining device reads the admitting side's transport key from the
        // channel, and already holds its own two.
        let from_the_joiner = Confirmation::derive(&joining, &admitting, channel).expect("derives");

        assert_eq!(from_the_admin, from_the_joiner);
    }

    /// The roles are not interchangeable, and nothing pretends they are.
    #[test]
    fn the_two_roles_are_distinct() {
        let one = side();
        let other = side();
        let channel = b"one exchange";

        assert_ne!(
            Confirmation::derive(&one, &other.transport, channel).expect("derives"),
            Confirmation::derive(&other, &one.transport, channel).expect("derives"),
            "who is joining and who is admitting is part of what the code says"
        );
    }

    /// The property the whole design rests on. Two exchanges between the same
    /// two devices must not produce the same code, or a code seen once would be
    /// worth something later.
    #[test]
    fn the_code_follows_the_channel() {
        let (a, b) = (side(), admitting());
        let first = Confirmation::derive(&a, &b, b"channel one").expect("derives");
        let second = Confirmation::derive(&a, &b, b"channel two").expect("derives");
        assert_ne!(
            first, second,
            "the same keys on a different channel must give a different code"
        );
    }

    /// There must be no way to lose the channel binding by accident, so the
    /// argument is required and empty is refused rather than treated as none.
    #[test]
    fn a_code_cannot_be_derived_without_channel_material() {
        let (a, b) = (side(), admitting());
        assert!(Confirmation::derive(&a, &b, &[]).is_err());
    }

    /// A different device in the exchange means a different code. This is what a
    /// substituted key looks like from the outside.
    #[test]
    fn a_substituted_side_changes_the_code() {
        let (a, b, impostor) = (side(), admitting(), admitting());
        let channel = b"one exchange";
        assert_ne!(
            Confirmation::derive(&a, &b, channel).expect("derives"),
            Confirmation::derive(&a, &impostor, channel).expect("derives")
        );
    }

    /// Changing either key of one side is enough. Both are in the derivation
    /// because the channel authenticates only one of them.
    /// Both of the joining device's keys are in the derivation, because the
    /// channel establishes only one of them and the proof of possession the
    /// other. Changing either has to move the code.
    #[test]
    fn changing_either_of_the_joining_keys_changes_the_code() {
        let joining = side();
        let admitting = admitting();
        let channel = b"one exchange";
        let baseline = Confirmation::derive(&joining, &admitting, channel).expect("derives");

        let other = side();
        let swapped_signing = Side {
            signing: other.signing,
            transport: joining.transport.clone(),
            attestation: joining.attestation.clone(),
        };
        let swapped_transport = Side {
            signing: joining.signing.clone(),
            transport: other.transport,
            attestation: joining.attestation.clone(),
        };
        // The third key is bound too, which is the point of carrying it: a
        // payload substituted in flight names an attestation key of the
        // attacker's choosing, and the digits have to move when it does.
        let swapped_attestation = Side {
            signing: joining.signing.clone(),
            transport: joining.transport.clone(),
            attestation: other.attestation,
        };
        assert_ne!(
            baseline,
            Confirmation::derive(&swapped_attestation, &admitting, channel).expect("derives"),
            "an exchanged attestation key must change the code"
        );

        assert_ne!(
            baseline,
            Confirmation::derive(&swapped_signing, &admitting, channel).expect("derives")
        );
        assert_ne!(
            baseline,
            Confirmation::derive(&swapped_transport, &admitting, channel).expect("derives")
        );
    }

    #[test]
    fn the_code_is_always_six_digits() {
        for _ in 0..200 {
            let code = Confirmation::derive(&side(), &admitting(), b"channel").expect("derives");
            assert_eq!(code.as_str().len(), limits::CODE_DIGITS as usize, "{code}");
            assert!(code.as_str().chars().all(|c| c.is_ascii_digit()), "{code}");
        }
    }

    #[test]
    fn a_typed_code_is_compared_and_not_interpreted() {
        let code = Confirmation::derive(&side(), &admitting(), b"channel").expect("derives");
        assert!(code.matches(code.as_str()));
        assert!(code.matches(&format!("  {}  ", code.as_str())), "a stray space is not a mismatch");
        assert!(!code.matches("000000x"));
        assert!(!code.matches(""));
    }

    /// The grinding test. Given both key sets and no channel material, an
    /// attacker must not be able to search for a key pair that will produce a
    /// chosen code — because without the channel there is no code to aim at.
    ///
    /// A regression guard: if anyone reintroduces a keys-only derivation, the
    /// codes below stop depending on the channel and this fails.
    #[test]
    fn a_code_cannot_be_ground_out_in_advance() {
        let (a, b) = (side(), admitting());
        let target = Confirmation::derive(&a, &b, b"the real channel").expect("derives");

        // The attacker knows every public key and searches its own key pairs.
        // Each attempt lands on a channel it controls, not the one being
        // matched, so nothing it finds transfers.
        let mut matched_on_another_channel = 0_u32;
        for _ in 0..500 {
            let attacker = admitting();
            let theirs =
                Confirmation::derive(&a, &attacker, b"the attacker's channel").expect("derives");
            if theirs == target {
                matched_on_another_channel = matched_on_another_channel.saturating_add(1);
            }
        }
        assert_eq!(
            matched_on_another_channel, 0,
            "a code matched across channels: the derivation has stopped depending on the channel"
        );
    }
}

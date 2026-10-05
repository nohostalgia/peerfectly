//! Between what a key store speaks and what the roster accepts.
//!
//! A key held outside this process comes with its platform's encodings, and they
//! are not the roster's. Nor are they each other's — which is the whole reason
//! this is a module and not two lines in one platform's file:
//!
//! | | public key | signature |
//! |---|---|---|
//! | Android's keystore | X.509 SubjectPublicKeyInfo | DER, `s` in either half |
//! | Windows CNG | `BCRYPT_ECCKEY_BLOB`: `X ‖ Y` | fixed `r‖s`, `s` in either half |
//! | what the roster takes | 33-byte compressed point | fixed `r‖s`, `s` low |
//!
//! Two key stores, two dialects, and neither of them the one the roster reads.
//! A third will bring a third.
//!
//! # Why this lives here and not in each platform's code
//!
//! It was written once, in the Android app, next to the keystore that needed it.
//! A second hardware custodian would have written it again, and then there would
//! be two answers to *what is this key* maintained by two people who never read
//! each other's file. A disagreement between them would not fail here: it would
//! produce a device id that differs from the one the peers derived, or a
//! signature that verifies on one platform and not on the next, which is a very
//! long way from the line that caused it.
//!
//! So the conversion is the capability's, made with the same curve
//! implementation [`roster`] verifies with, and a custodian supplies bytes rather
//! than opinions.
//!
//! # Refusing is part of the job
//!
//! Bytes that are not a P-256 key, or not a DER signature, are refused here and
//! named. The alternative is handing the roster something structurally wrong and
//! learning about it from a rejection whose message is about a signature rather
//! than about a key store returning something unexpected.

use crate::error::{Error, Result};

/// The 33-byte compressed point behind a key store's SubjectPublicKeyInfo.
///
/// # Errors
///
/// When the bytes are not a P-256 public key.
pub fn public_key_from_spki(spki: &[u8]) -> Result<Vec<u8>> {
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    use p256::pkcs8::DecodePublicKey as _;

    let key =
        p256::PublicKey::from_public_key_der(spki).map_err(|cause| Error::CustodianFailed {
            detail: format!("the key store's public key did not decode as P-256: {cause}"),
        })?;
    Ok(key.to_sec1_point(true).as_bytes().to_vec())
}

/// The fixed-width, low-`s` `r‖s` behind a key store's DER signature.
///
/// The roster refuses a high `s`, and a key store is free to produce one: which
/// half it lands in is not a property the signer chooses. Normalising is
/// therefore part of reading the signature, not a correction applied to it — the
/// two forms are the same signature.
///
/// # Errors
///
/// When the bytes are not a DER ECDSA signature over P-256.
pub fn signature_from_der(der: &[u8]) -> Result<Vec<u8>> {
    let signature =
        p256::ecdsa::Signature::from_der(der).map_err(|cause| Error::CustodianFailed {
            detail: format!("the key store's signature did not decode as DER P-256: {cause}"),
        })?;
    Ok(signature.normalize_s().to_bytes().to_vec())
}

/// The 33-byte compressed point behind an affine point given as `X` and `Y`.
///
/// What CNG hands back for an ECDSA key: a `BCRYPT_ECCKEY_BLOB` header followed
/// by the two coordinates, big-endian and unpadded to the curve's size. The
/// caller passes the two halves; reading the header is the platform's business
/// and the curve is this crate's.
///
/// # Errors
///
/// When the coordinates are not the size P-256 uses, or do not lie on the curve.
pub fn public_key_from_point(x: &[u8], y: &[u8]) -> Result<Vec<u8>> {
    use p256::elliptic_curve::sec1::ToSec1Point as _;

    let wrong = |what: &str| Error::CustodianFailed {
        detail: format!("the key store's public key is not a P-256 point: {what}"),
    };
    if x.len() != 32 || y.len() != 32 {
        return Err(wrong(&format!(
            "the coordinates are {} and {} bytes, not 32",
            x.len(),
            y.len()
        )));
    }

    // SEC1 uncompressed: `04 ‖ X ‖ Y`. Built here and handed to the curve, which
    // is what checks that the point is on it — a pair of numbers of the right
    // length is not a key.
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);

    let key = p256::PublicKey::from_sec1_bytes(&sec1).map_err(|cause| wrong(&cause.to_string()))?;
    Ok(key.to_sec1_point(true).as_bytes().to_vec())
}

/// The low-`s` form of a signature already given as fixed-width `r‖s`.
///
/// What CNG's `NCryptSignHash` produces for ECDSA — not DER, which is what a
/// keystore on a phone produces for the same curve and the same key. It is the
/// roster's own shape already, except that `s` may be in either half of the
/// group and the roster takes only the low one.
///
/// # Errors
///
/// When the bytes are not 64, or are not a signature over P-256.
pub fn signature_from_fixed(raw: &[u8]) -> Result<Vec<u8>> {
    let signature =
        p256::ecdsa::Signature::from_slice(raw).map_err(|cause| Error::CustodianFailed {
            detail: format!("the key store's signature is not a fixed P-256 one: {cause}"),
        })?;
    Ok(signature.normalize_s().to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Signer as _;
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    use p256::pkcs8::EncodePublicKey as _;
    use roster::sign::PublicKey;
    use roster::types::Algorithm;

    use super::*;

    fn signing_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_bytes(&[0x21; 32].into()).expect("a key")
    }

    fn spki_of(key: &p256::ecdsa::SigningKey) -> Vec<u8> {
        key.verifying_key().to_public_key_der().expect("der").as_bytes().to_vec()
    }

    fn roster_key(key: &p256::ecdsa::SigningKey) -> PublicKey {
        PublicKey::new(Algorithm::P256, public_key_from_spki(&spki_of(key)).expect("converts"))
            .expect("a roster key")
    }

    #[test]
    fn a_key_stores_public_key_becomes_the_compressed_point() {
        let compressed = public_key_from_spki(&spki_of(&signing_key())).expect("converts");
        assert_eq!(33, compressed.len(), "the roster's form is 33 bytes");
        assert!(
            matches!(compressed.first(), Some(0x02 | 0x03)),
            "and a compressed point says which half y is in"
        );
    }

    #[test]
    fn a_der_signature_verifies_under_the_rosters_own_check() {
        let key = signing_key();
        let message = b"the bytes the roster would sign";
        let signature: p256::ecdsa::Signature = key.sign(message);

        let converted = signature_from_der(signature.to_der().as_bytes()).expect("converts");
        assert_eq!(64, converted.len(), "fixed width, not DER's variable one");
        roster_key(&key).verify(message, &converted).expect("verifies as the roster checks");
    }

    /// A key store may return `s` in the high half. The roster refuses that form,
    /// so reading the signature includes normalising it — and what comes out must
    /// still be the same signature.
    #[test]
    fn a_high_s_signature_is_normalised_and_still_verifies() {
        let key = signing_key();
        let message = b"the bytes the roster would sign";
        let low: p256::ecdsa::Signature = key.sign(message);
        let (r, s) = low.split_scalars();
        let high = p256::ecdsa::Signature::from_scalars(r, -*s).expect("the other form");
        assert_ne!(high.to_bytes(), low.to_bytes(), "the high form really is different");
        assert!(
            roster_key(&key).verify(message, &high.to_bytes()).is_err(),
            "and the roster really does refuse it, which is why this conversion exists"
        );

        let converted = signature_from_der(high.to_der().as_bytes()).expect("converts");
        roster_key(&key).verify(message, &converted).expect("normalised, it verifies");
    }

    #[test]
    fn bytes_that_are_not_a_key_are_named() {
        let refusal = public_key_from_spki(b"not a key").expect_err("refused");
        let said = refusal.to_string();
        assert!(said.contains("public key"), "the message says which one failed: {said}");
    }

    #[test]
    fn bytes_that_are_not_a_signature_are_named() {
        let refusal = signature_from_der(b"not a signature").expect_err("refused");
        let said = refusal.to_string();
        assert!(said.contains("signature"), "the message says which one failed: {said}");
    }

    /// A raw signature offered where DER is expected is refused rather than
    /// passed through: 64 bytes are a plausible length for both, and letting one
    /// through would produce a value the roster refuses far from here.
    #[test]
    fn a_signature_that_is_not_der_is_refused_even_at_the_right_length() {
        let key = signing_key();
        let signature: p256::ecdsa::Signature = key.sign(b"anything");
        let raw = signature.to_bytes().to_vec();
        assert_eq!(64, raw.len());
        assert!(signature_from_der(&raw).is_err(), "the right length is not the right encoding");
    }

    #[test]
    fn a_key_stores_coordinates_become_the_compressed_point() {
        let key = signing_key();
        let public = p256::PublicKey::from(*key.verifying_key());
        let point = public.to_sec1_point(false);
        let bytes = point.as_bytes();
        let (x, y) = bytes.get(1..33).zip(bytes.get(33..65)).expect("an uncompressed point");

        let compressed = public_key_from_point(x, y).expect("converts");
        assert_eq!(
            public_key_from_spki(&spki_of(&key)).expect("converts"),
            compressed,
            "two dialects, one key, one answer"
        );
    }

    #[test]
    fn coordinates_of_the_wrong_size_are_named() {
        let refusal = public_key_from_point(&[0x01; 31], &[0x02; 32]).expect_err("refused");
        assert!(refusal.to_string().contains("32"), "{refusal}");
    }

    /// Two numbers of the right length are not a key, and the curve is what says
    /// so rather than a length check pretending to.
    #[test]
    fn a_point_that_is_not_on_the_curve_is_refused() {
        assert!(public_key_from_point(&[0x01; 32], &[0x02; 32]).is_err());
    }

    #[test]
    fn a_fixed_width_signature_is_normalised_and_verifies() {
        let key = signing_key();
        let message = b"the bytes the roster would sign";
        let low: p256::ecdsa::Signature = key.sign(message);
        let (r, s) = low.split_scalars();
        let high = p256::ecdsa::Signature::from_scalars(r, -*s).expect("the other form");

        let converted = signature_from_fixed(&high.to_bytes()).expect("converts");
        assert_eq!(64, converted.len());
        roster_key(&key).verify(message, &converted).expect("normalised, it verifies");
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_named() {
        let refusal = signature_from_fixed(&[0x01; 63]).expect_err("refused");
        assert!(refusal.to_string().contains("signature"), "{refusal}");
    }

    /// The two dialects meet here, and must agree: the same key and the same act
    /// signed on a phone and on a desktop produce the same 64 bytes.
    #[test]
    fn the_two_dialects_give_one_answer() {
        let key = signing_key();
        let message = b"one act, signed once";
        let signature: p256::ecdsa::Signature = key.sign(message);

        let from_a_phone = signature_from_der(signature.to_der().as_bytes()).expect("converts");
        let from_a_desktop = signature_from_fixed(&signature.to_bytes()).expect("converts");
        assert_eq!(from_a_phone, from_a_desktop, "DER and fixed are one signature");
        roster_key(&key).verify(message, &from_a_phone).expect("and it verifies");
    }

    /// The scenario two platforms cannot be made to fail separately: whatever
    /// each key store calls it, the same key and the same signature convert to
    /// the same bytes, because neither platform decides anything here.
    #[test]
    fn two_custodians_on_different_platforms_agree() {
        let key = signing_key();
        let message = b"one act, signed once";

        // Two key stores report the same key. One hands back the SPKI with no
        // more thought; the other happens to hold the high-`s` form of the same
        // signature. Neither converted anything itself.
        let first_key = public_key_from_spki(&spki_of(&key)).expect("converts");
        let second_key = public_key_from_spki(&spki_of(&key)).expect("converts");
        assert_eq!(first_key, second_key, "the same key is the same key");

        let low: p256::ecdsa::Signature = key.sign(message);
        let (r, s) = low.split_scalars();
        let high = p256::ecdsa::Signature::from_scalars(r, -*s).expect("the other form");

        let from_first = signature_from_der(low.to_der().as_bytes()).expect("converts");
        let from_second = signature_from_der(high.to_der().as_bytes()).expect("converts");
        assert_eq!(
            from_first, from_second,
            "one signature, whichever half the platform's implementation put s in"
        );
        roster_key(&key).verify(message, &from_first).expect("and it verifies");
    }
}

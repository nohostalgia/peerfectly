//! Base32 as RFC 4648 writes it, lower case and without padding: the text an
//! invite is carried in.
//!
//! Lower case because it is read and copied by people beside a lower-case
//! prefix; either case is read, since case carries nothing here. Anything else
//! is refused rather than repaired: padding, a character outside the alphabet,
//! a length no byte string has, or bits left over that are not zero, so one
//! byte string has exactly one text.

use alloc::string::String;
use alloc::vec::Vec;

/// The alphabet, in lower case.
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// `bytes` as text.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in bytes {
        buffer = buffer.wrapping_shl(8) | u32::from(*byte);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            out.push(symbol(buffer.wrapping_shr(bits)));
        }
        buffer &= low(bits);
    }
    if bits > 0 {
        out.push(symbol(buffer.wrapping_shl(5_u32.saturating_sub(bits))));
    }
    out
}

/// The bytes `text` holds, or `None` where it is not canonical base32.
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    // Lengths 1, 3 and 6 modulo 8 hold no whole number of bytes.
    if matches!(text.len().rem_euclid(8), 1 | 3 | 6) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len().saturating_mul(5).div_euclid(8));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for character in text.bytes() {
        buffer = buffer.wrapping_shl(5) | u32::from(value_of(character)?);
        bits = bits.saturating_add(5);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from(buffer.wrapping_shr(bits)).ok()?);
            buffer &= low(bits);
        }
    }
    // What is left over must be zero: another text for the same bytes otherwise.
    (buffer == 0).then_some(out)
}

/// The lowest `bits` bits set.
const fn low(bits: u32) -> u32 {
    1_u32.wrapping_shl(bits).wrapping_sub(1)
}

fn symbol(value: u32) -> char {
    let index = usize::try_from(value & 0x1f).unwrap_or(0);
    ALPHABET.get(index).copied().map_or('a', char::from)
}

fn value_of(character: u8) -> Option<u8> {
    match character {
        b'a'..=b'z' => Some(character.wrapping_sub(b'a')),
        b'A'..=b'Z' => Some(character.wrapping_sub(b'A')),
        b'2'..=b'7' => Some(character.wrapping_sub(b'2').wrapping_add(26)),
        _ => None,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "a test reports failure by panicking, and slices what it built"
)]
mod tests {
    use super::*;

    /// The test vectors of RFC 4648, §10, without their padding.
    #[test]
    fn the_rfc_vectors() {
        for (bytes, text) in [
            (&b""[..], ""),
            (b"f", "my"),
            (b"fo", "mzxq"),
            (b"foo", "mzxw6"),
            (b"foob", "mzxw6yq"),
            (b"fooba", "mzxw6ytb"),
            (b"foobar", "mzxw6ytboi"),
        ] {
            assert_eq!(encode(bytes), text);
            assert_eq!(decode(text).unwrap(), bytes);
            assert_eq!(decode(&text.to_uppercase()).unwrap(), bytes, "either case");
        }
    }

    #[test]
    fn every_length_and_value_round_trips() {
        let bytes: Vec<u8> = (0..=255).collect();
        for len in 0..bytes.len() {
            let slice = &bytes[..len];
            assert_eq!(decode(&encode(slice)).unwrap(), slice);
        }
    }

    #[test]
    fn what_is_not_canonical_is_refused() {
        assert!(decode("my======").is_none(), "padding");
        assert!(decode("m1").is_none(), "outside the alphabet");
        assert!(decode("mzx").is_none(), "a length no bytes have");
        assert!(decode("mz").is_none(), "bits left over that are not zero");
    }
}

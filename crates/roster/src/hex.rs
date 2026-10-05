//! Lowercase hex, for the test-vector corpus.
//!
//! The corpus stores every byte string as hex so that a person diagnosing a
//! divergence between two implementations can read it. That corpus is also
//! produced by a binary in this crate, which cannot reach a dev-dependency, so
//! the conversion lives here rather than being pulled in.

/// Encodes bytes as lowercase hex.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decodes lowercase or uppercase hex, returning `None` for anything that is
/// not an even-length run of hex digits.
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    // Bitwise rather than `% 2`, which the arithmetic lint refuses, and
    // rather than `is_multiple_of`, which is newer than the declared MSRV.
    if text.len() & 1 != 0 {
        return None;
    }
    let digits = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() >> 1);
    for pair in digits.chunks_exact(2) {
        let (high, low) = match pair {
            [high, low] => (*high, *low),
            _ => return None,
        };
        let value = nibble(high)?.checked_mul(16)?.checked_add(nibble(low)?)?;
        out.push(value);
    }
    Some(out)
}

/// One hex digit's value.
fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => digit.checked_sub(b'0'),
        b'a'..=b'f' => digit.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        b'A'..=b'F' => digit.checked_sub(b'A').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(decode(&encode(&bytes)), Some(bytes));
    }

    #[test]
    fn encodes_lowercase_padded() {
        assert_eq!(encode(&[0x00, 0x0f, 0xff]), "000fff");
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(decode("abc"), None, "odd length");
        assert_eq!(decode("zz"), None, "not hex digits");
    }

    #[test]
    fn accepts_uppercase() {
        assert_eq!(decode("FF"), Some(vec![0xff]));
    }
}

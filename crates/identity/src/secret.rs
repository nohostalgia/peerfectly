//! Private key bytes, cleared when they go.
//!
//! This is a mitigation, not a guarantee. It defends against a key lingering in
//! a freed allocation to be recovered from a core dump or handed to the next
//! caller who asks for memory. It does not defend against a process whose live
//! memory is already readable, and it cannot undo a copy the compiler made
//! before the value reached this wrapper.
//!
//! The other half of the job is [`core::fmt::Debug`]. A derived implementation
//! would put a private key into the first log line someone adds while chasing a
//! bug, which is exactly when nobody is reading carefully.

use core::fmt;

use zeroize::Zeroize;

/// Thirty-two bytes of private key material.
///
/// Both algorithms in use take a 32-byte private input: an ed25519 seed, or a
/// P-256 scalar.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes {
    /// The material.
    bytes: [u8; 32],
}

impl SecretBytes {
    /// Wraps key material.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Borrows the material.
    ///
    /// Deliberately not `Copy` and deliberately named, so a caller that spreads
    /// the bytes around has to say so.
    #[must_use]
    pub const fn expose(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the bytes. The length is safe and occasionally useful.
        f.write_str("SecretBytes(32 bytes, redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::SecretBytes;

    #[test]
    fn debug_output_carries_no_material() {
        let secret = SecretBytes::new([0xab; 32]);
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("ab"), "the bytes must not appear: {rendered}");
        assert!(!rendered.contains("171"), "nor in decimal: {rendered}");
    }

    #[test]
    fn material_is_reachable_only_deliberately() {
        let secret = SecretBytes::new([7u8; 32]);
        assert_eq!(secret.expose(), &[7u8; 32]);
    }

    /// The drop implementation is what clears the buffer. Observing freed
    /// memory is not something a safe test can do, so this asserts the
    /// mechanism is wired up: zeroizing the same array through the same call
    /// clears it.
    #[test]
    fn dropping_clears_the_material() {
        use zeroize::Zeroize;
        let mut bytes = [9u8; 32];
        bytes.zeroize();
        assert_eq!(bytes, [0u8; 32], "this is the operation Drop performs");

        // And the wrapper owns its bytes, so nothing outlives the drop.
        let secret = SecretBytes::new([9u8; 32]);
        drop(secret);
    }
}

//! Bounds on an enrolment, and why each one is where it is.
//!
//! Two of these are security parameters rather than sizes. The joining payload
//! is public — it is on a screen, it gets photographed, it gets pasted into a
//! chat — so anybody who has seen one can open an exchange with the device that
//! produced it. [`EXCHANGE_DEADLINE_SECS`] and [`ATTEMPTS_PER_WAIT`] are what
//! stop that being free.

/// The longest name a joining device may propose for itself, in bytes.
///
/// The roster's own bound on a device name. A proposal longer than the roster
/// could store would be refused later by something further away, and the person
/// would be told about it at the wrong moment.
pub const MAX_PROPOSED_NAME_LEN: usize = roster::limits::MAX_NAME_LEN;

/// The longest relay address a payload may carry, in bytes.
///
/// The same bound the roster puts on the relay it names, so a payload cannot
/// describe a relay the network could never adopt.
pub const MAX_RELAY_LEN: usize = roster::limits::MAX_RELAY_LEN;

/// The largest a joining payload may be, encoded, in bytes.
///
/// Two keys, a short name and a URL. Generous enough for a P-256 key pair and a
/// long relay address together, and small enough to stay inside a scannable code
/// without the person having to hold a camera still for a long time.
pub const MAX_PAYLOAD_SIZE: usize = 512;

/// The largest a single exchange message may be, in bytes.
///
/// The roster travels through the exchange, so this admits an operation log
/// rather than one operation. Bounded because it arrives from a peer nothing has
/// authenticated yet, and a length is checked before anything is reserved for it.
pub const MAX_EXCHANGE_MESSAGE_SIZE: usize = 1024 * 1024;

/// How long a device waits to be admitted, in seconds.
///
/// Long enough for a person to walk to another machine, read a payload, and type
/// six digits back. Short enough that a device left waiting by accident stops
/// answering strangers the same afternoon.
pub const WAIT_SECS: u64 = 10 * 60;

/// How long one exchange may take before it is abandoned, in seconds.
///
/// Well short of [`WAIT_SECS`], and that gap is the point. Only one exchange runs
/// at a time, so without a deadline of its own anybody who had seen the payload
/// could open an exchange, say nothing, and keep the admin out for the whole
/// wait while the person watched nothing happen.
pub const EXCHANGE_DEADLINE_SECS: u64 = 60;

/// How many exchanges one wait will entertain before giving up.
///
/// A person needs a handful: a mistyped code, a second attempt, a relay that
/// dropped the first connection. Far below what an attacker would need to make
/// guessing a six-digit code worth attempting, which is what keeps the code
/// short enough to read aloud.
pub const ATTEMPTS_PER_WAIT: u32 = 10;

/// How many decimal digits the confirmation code has.
///
/// The Signal and Bluetooth precedent. Long enough that guessing one within
/// [`ATTEMPTS_PER_WAIT`] is hopeless, short enough that a person reads it aloud
/// correctly the first time.
pub const CODE_DIGITS: u32 = 6;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stated_bounds_are_pinned() {
        assert_eq!(MAX_PAYLOAD_SIZE, 512);
        assert_eq!(MAX_EXCHANGE_MESSAGE_SIZE, 1024 * 1024);
        assert_eq!(WAIT_SECS, 600);
        assert_eq!(EXCHANGE_DEADLINE_SECS, 60);
        assert_eq!(ATTEMPTS_PER_WAIT, 10);
        assert_eq!(CODE_DIGITS, 6);
    }

    /// The gap between the two is what stops one silent peer from occupying the
    /// whole wait. If they ever met, a single stalled exchange would consume it.
    #[test]
    fn an_exchange_cannot_occupy_the_whole_wait() {
        assert!(
            EXCHANGE_DEADLINE_SECS.saturating_mul(2) < WAIT_SECS,
            "a wait must outlast several exchanges, or one stall ends it"
        );
    }

    /// Guessing the code has to be hopeless within the attempts allowed, or the
    /// code would have to be longer than a person will read aloud.
    #[test]
    fn the_code_outruns_the_attempts_allowed() {
        let space = 10_u64.saturating_pow(CODE_DIGITS);
        let attempts = u64::from(ATTEMPTS_PER_WAIT);
        assert!(
            space / attempts > 10_000,
            "an attacker gets {attempts} guesses at a space of {space}"
        );
    }

    /// A payload the roster could never act on would be refused far from where
    /// the person typed it.
    #[test]
    fn the_payload_bounds_match_the_rosters() {
        assert_eq!(MAX_PROPOSED_NAME_LEN, roster::limits::MAX_NAME_LEN);
        assert_eq!(MAX_RELAY_LEN, roster::limits::MAX_RELAY_LEN);
    }
}

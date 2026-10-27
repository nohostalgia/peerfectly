//! Bounds on an enrolment, and why each one is where it is.
//!
//! Two of these are security parameters rather than sizes. An invite travels by
//! message and gets photographed, so anybody who has seen one can open an
//! exchange with the device waiting behind it. [`EXCHANGE_DEADLINE_SECS`] and
//! [`ATTEMPTS_PER_WAIT`] are what stop that being free.

/// The longest name a joining device may propose for itself, in bytes.
///
/// The roster's own bound on a device name. A proposal longer than the roster
/// could store would be refused later by something further away, and the person
/// would be told about it at the wrong moment.
pub const MAX_PROPOSED_NAME_LEN: usize = roster::limits::MAX_NAME_LEN;

/// The longest relay address an invite may carry, in bytes.
///
/// The same bound the roster puts on the relay it names, so an invite cannot
/// describe a relay the network could never adopt.
pub const MAX_RELAY_LEN: usize = roster::limits::MAX_RELAY_LEN;

/// The largest a single exchange message may be, in bytes.
///
/// The roster travels through the exchange, so this admits an operation log
/// rather than one operation. Bounded because it arrives from a peer nothing has
/// authenticated yet, and a length is checked before anything is reserved for it.
pub const MAX_EXCHANGE_MESSAGE_SIZE: usize = 1024 * 1024;

/// How long one message of an exchange may take before the exchange is
/// abandoned, in seconds.
///
/// A join has no deadline of its own: it waits until it is admitted or
/// cancelled. Each exchange does, and that is the point. Only one runs at a
/// time on the joining device, so without one anybody who had seen the invite
/// could open an exchange, say nothing, and keep the admin out for as long as
/// they liked. Nothing in an exchange waits on a person, so a minute is
/// generous.
pub const EXCHANGE_DEADLINE_SECS: u64 = 60;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stated_bounds_are_pinned() {
        assert_eq!(MAX_EXCHANGE_MESSAGE_SIZE, 1024 * 1024);
        assert_eq!(EXCHANGE_DEADLINE_SECS, 60);
    }

    /// A name or relay the roster could never act on would be refused far from
    /// where the person gave it.
    #[test]
    fn the_bounds_match_the_rosters() {
        assert_eq!(MAX_PROPOSED_NAME_LEN, roster::limits::MAX_NAME_LEN);
        assert_eq!(MAX_RELAY_LEN, roster::limits::MAX_RELAY_LEN);
    }
}

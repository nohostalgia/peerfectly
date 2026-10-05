//! The wall clock, for the two things this daemon shows a person and decides
//! nothing with.
//!
//! `DESIGN.md` §0 is emphatic that a timestamp must not influence ordering,
//! conflict resolution or validity, and nothing that reads these does. They exist
//! because the screens a person decides from are titled by *when*: a revocation
//! signed at a given minute, a device last in contact at another.
//!
//! # The minute, not the millisecond
//!
//! An operation's time is copied to every member and stays in the roster for as
//! long as the network exists. It is metadata about when a person acted, and two
//! identities of one machine signing in two networks at the same millisecond would
//! be linkable by it. The screens show minutes, so minutes are all that is kept.

use std::time::{Duration, SystemTime};

/// Milliseconds in a minute.
const MINUTE_MS: u64 = 60_000;

/// Below this, a value in an operation's time field is not a time.
///
/// September 2001, in milliseconds. Until `membership-report` the daemon put a
/// counter in that field — 1 for a founding, the log's length for anything after
/// — and every operation signed that way is still in somebody's roster. Any
/// counter a log could reach is far below this, and a real clock set before 2001
/// is not worth telling apart from one.
pub(crate) const PLAUSIBLE_MS: u64 = 1_000_000_000_000;

/// This device's clock, floored to the minute, in milliseconds since the epoch.
///
/// What an operation signed here carries as its time. A clock before the epoch
/// yields zero, which then reads as no time recorded rather than as 1970.
#[must_use]
pub(crate) fn signing_time() -> u64 {
    floor_to_minute(now_ms())
}

/// This device's clock, in whole minutes since the epoch.
#[must_use]
pub(crate) fn minute_now() -> u64 {
    now_ms().checked_div(MINUTE_MS).unwrap_or(0)
}

/// A whole minute since the epoch, as a point in time.
#[must_use]
pub(crate) fn minute_as_time(minute: u64) -> Option<SystemTime> {
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(minute.checked_mul(60)?))
}

/// An operation's time field, as a point in time if it is one.
#[must_use]
pub(crate) fn operation_time(ts: u64) -> Option<SystemTime> {
    if ts < PLAUSIBLE_MS {
        return None;
    }
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_millis(ts))
}

/// Milliseconds since the epoch, or zero for a clock set before it.
///
/// Public because an act waiting for a signature is timed by it — how long a
/// person has been at a prompt, which is a duration and not an ordering, so it
/// stays inside what this module's doc allows a clock to be used for.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
}

/// Drops everything below the minute.
const fn floor_to_minute(ms: u64) -> u64 {
    ms.saturating_sub(ms % MINUTE_MS)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    #[test]
    fn a_signing_time_is_a_whole_minute_and_now() {
        let before = now_ms();
        let signed = signing_time();
        assert_eq!(signed % MINUTE_MS, 0, "nothing below the minute is kept");
        assert!(signed <= before.saturating_add(MINUTE_MS), "{signed} is not now");
        assert!(signed.saturating_add(MINUTE_MS) > before, "{signed} is not now");
        assert!(operation_time(signed).is_some(), "and it reads back as a time");
    }

    /// Every operation this daemon signed before now carries a counter there.
    #[test]
    fn a_counter_is_not_a_time() {
        for counter in [0, 1, 3, 4_096, 1_000_000] {
            assert!(operation_time(counter).is_none(), "{counter} would render as 1970");
        }
    }

    #[test]
    fn a_minute_reads_back_as_the_same_minute() {
        let minute = minute_now();
        let time = minute_as_time(minute).unwrap();
        let seconds = time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(seconds, minute.saturating_mul(60));
    }
}

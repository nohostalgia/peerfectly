//! When the daemon does the things other crates left it to decide.
//!
//! `roster-sync` has no loop, `local-discovery` no announcement schedule. Each of them said so plainly and deferred here. This
//! is that decision, in one place, with the reasoning next to the numbers.
//!
//! # Some are findings now
//!
//! These were all chosen by argument at first, and written together so that the
//! first measurement would have something specific to contradict. It did. On
//! 2026-10-07 the testbed measured what an idle device spent: about 3.7 GB a
//! month with one peer up, and between 2.8 and 11 GB with one switched off
//! (`crates/linux-daemon/VERIFICATION.md`, step 32). The sixty-second sync, which
//! dialled every member and offered it everything, and the five-second
//! announcements were most of it. [`Schedule::sync`], [`Schedule::announce`]
//! and [`Schedule::idle`] are set from that measurement, and say so where they
//! are defined.
//!
//! `endpoint_cache` is still argued rather than measured. If it is still
//! unchanged after the daemon has run on a real machine for a week, that is a
//! sign nobody looked — not a sign it was right.

use core::time::Duration;

/// The intervals the daemon runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    /// How often to reconcile with the neighbours and the open sessions.
    ///
    /// Sync also runs on every session establishment and whenever an operation is
    /// admitted, which is how operations actually travel: each is pushed at once.
    /// This tick is only the safety net for a push that was lost, so an hour, not
    /// the minute it was: every minute, it cost every device a contact with every
    /// member around the clock — the recurring traffic measured on 2026-10-07 at
    /// gigabytes a month.
    pub sync: Duration,

    /// How often to announce on the local network when nothing has changed.
    ///
    /// A minute. It was five seconds, which measured on 2026-10-07 as about
    /// 0.35 GB a month of multicast on a quiet network. What the short interval
    /// was for — `local-discovery` records that multicast on Wi-Fi is filtered or
    /// delivered at low bitrates, so a single announcement is not evidence of
    /// anything — matters when something has just changed, not every five seconds
    /// for ever: a change of interfaces is announced at once and then
    /// [`ANNOUNCE_REPEATS`] more times, [`crate::limits::INTERFACE_RECHECK`] apart.
    pub announce: Duration,

    /// How long a cached endpoint is worth offering to the transport.
    ///
    /// §2.6b puts the restore path under 500 ms using cached endpoints, so this
    /// has to outlive an ordinary overnight gap. A stale entry costs one packet;
    /// a missing one leaves the first session to the relay.
    pub endpoint_cache: Duration,

    /// How long a session may carry nothing before it is closed.
    ///
    /// A session is opened by the first packet that needs it, so a closed one
    /// costs the next packet a reopening: a handshake of a few kilobytes and a
    /// pause of tens to hundreds of milliseconds. An open one costs nothing on
    /// the wire — convesso sends no keep-alive for a session, and forgets one
    /// whose keys expired — only what the daemon holds for it. Ten minutes keeps
    /// a session through the ordinary pauses of someone working — reading a
    /// page, thinking between commands — and closes it once they have stopped.
    ///
    /// Not a session with a light member: that one stays open, the way a new
    /// root reaches the light member (`node::held_open`).
    pub idle: Duration,
}

impl Schedule {
    /// The provisional schedule, pending measurement.
    #[must_use]
    pub const fn provisional() -> Self {
        Self {
            sync: Duration::from_secs(60 * 60),
            announce: Duration::from_secs(60),
            endpoint_cache: Duration::from_secs(24 * 60 * 60),
            idle: Duration::from_secs(10 * 60),
        }
    }
}

/// How many more times a change of interfaces is announced, after the first.
///
/// Three announcements in all, a few seconds apart, so that one lost to Wi-Fi
/// multicast does not leave a device on the relay for the next minute.
pub const ANNOUNCE_REPEATS: u8 = 2;

impl Default for Schedule {
    fn default() -> Self {
        Self::provisional()
    }
}

/// Decides when a local announcement is worth sending.
///
/// Two triggers, and the second is the one that matters.
///
/// The tick is because multicast on Wi-Fi is unreliable — `local-discovery`
/// records that it is filtered or delivered at low bitrates often enough that a
/// single announcement is not evidence of anything. Repetition is the whole
/// mitigation.
///
/// The **interface change** is the trigger that makes the difference a person
/// notices. A laptop that moves from mobile tethering to home Wi-Fi is suddenly
/// half a metre from its own server, and if it waits for the next tick it stays
/// on the relay in the meantime. `local-discovery` puts it plainly: not
/// connecting while standing next to the machine is an absurd failure for a
/// product sold on sovereignty.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Announcing {
    /// The interfaces seen last time, in the order the platform gave them.
    last: Option<Vec<String>>,
}

impl Announcing {
    /// Nothing announced yet.
    #[must_use]
    pub const fn new() -> Self {
        Self { last: None }
    }

    /// Whether to announce now.
    ///
    /// `tick_due` carries the repeating interval; the interfaces are compared
    /// against the last time regardless, so a change announces immediately
    /// without waiting for it.
    pub fn should_announce(&mut self, interfaces: &[String], tick_due: bool) -> bool {
        let changed = match &self.last {
            None => true,
            Some(previous) => previous.as_slice() != interfaces,
        };
        if changed {
            self.last = Some(interfaces.to_vec());
        }
        changed || tick_due
    }

    /// Whether the interfaces differ from the last announcement.
    #[must_use]
    pub fn would_change(&self, interfaces: &[String]) -> bool {
        self.last.as_ref().is_none_or(|previous| previous.as_slice() != interfaces)
    }

    /// Forgets what was seen, so the next observation counts as a change.
    pub fn forget(&mut self) {
        self.last = None;
    }
}

/// Decides when a change in this device's interfaces is one to act on.
///
/// Acted on once it has held for [`Settling::STEADY`] checks in a row, and only
/// if it differs from what was last acted on. Measured on 2026-10-08: a Windows
/// PC's list changed and changed back five seconds later every eight to twenty
/// minutes, with nothing moving. Each change made it catch up with its
/// neighbours, which opened a session with the phone and kept it ten minutes,
/// so the phone at rest spent about 800 MB a month on keep-alives (Android
/// `VERIFICATION.md`, step 33). A change that undoes itself loses no push, so
/// there is nothing to catch up on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settling<T> {
    /// What was last acted on: the list as the daemon started, at first.
    acted_on: T,
    /// A different list, and how many checks in a row it has held.
    pending: Option<(T, u32)>,
}

impl<T: PartialEq + Clone> Settling<T> {
    /// How many checks in a row a new list must hold, at
    /// [`crate::limits::NETWORK_CHECK`] each: thirty seconds. Late enough to let
    /// a flicker pass, early enough that a device that really moved catches up
    /// within a minute.
    pub const STEADY: u32 = 30;

    /// Starting from what is there now, which is not a change.
    pub const fn new(current: T) -> Self {
        Self { acted_on: current, pending: None }
    }

    /// One check: whether the list has now settled on something new.
    pub fn observe(&mut self, now: T) -> bool {
        if now == self.acted_on {
            self.pending = None;
            return false;
        }
        let held = match self.pending.take() {
            Some((list, count)) if list == now => count.saturating_add(1),
            _ => 1,
        };
        if held >= Self::STEADY {
            self.acted_on = now;
            true
        } else {
            self.pending = Some((now, held));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A list that changes and changes back is never acted on.
    #[test]
    fn a_change_that_undoes_itself_is_not_acted_on() {
        let mut settling = Settling::new("wifi");
        assert!(!settling.observe("wifi, flicker"));
        assert!(!settling.observe("wifi"));
        for _ in 0..20 {
            assert!(!settling.observe("wifi"));
        }
    }

    /// A list that holds is acted on once, after it has held, and not again.
    #[test]
    fn a_change_that_holds_is_acted_on_once() {
        let mut settling = Settling::new("home");
        for _ in 1..Settling::<&str>::STEADY {
            assert!(!settling.observe("hotel"));
        }
        assert!(settling.observe("hotel"), "acted on at the last of its steady checks");
        for _ in 0..20 {
            assert!(!settling.observe("hotel"), "and not again while it holds");
        }
        for _ in 1..Settling::<&str>::STEADY {
            assert!(!settling.observe("home"));
        }
        assert!(settling.observe("home"), "going back is a change too, once it holds");
    }

    /// A list that keeps changing is not acted on until one of them holds.
    #[test]
    fn a_list_that_keeps_changing_waits_for_one_to_hold() {
        let mut settling = Settling::new(0_u32);
        for step in 1..=20 {
            assert!(!settling.observe(step), "nothing holds while every check differs");
        }
        // The last of them has held once already.
        for _ in 2..Settling::<u32>::STEADY {
            assert!(!settling.observe(20));
        }
        assert!(settling.observe(20));
    }

    fn addresses(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    /// The numbers are provisional, and the point is that they are together.
    #[test]
    fn the_schedule_is_in_one_place() {
        let schedule = Schedule::provisional();
        assert!(schedule.announce < schedule.sync, "announcing is cheap and unreliable");
        // Operations are pushed the moment they are admitted, and the sync tick
        // only catches a push that was lost.
        assert!(schedule.sync >= Duration::from_secs(60 * 60), "a safety net, not the transport");
    }

    /// A quiet network hears one announcement a minute, and a change a few in
    /// quick succession: the cost at rest is the minute, and the burst is what
    /// survives Wi-Fi dropping one.
    #[test]
    fn announcing_is_a_minute_at_rest_and_a_burst_on_change() {
        let schedule = Schedule::provisional();
        assert_eq!(schedule.announce, Duration::from_secs(60));
        assert!((1..=3).contains(&ANNOUNCE_REPEATS), "a few repeats, not a stream");
        let burst = crate::limits::INTERFACE_RECHECK
            .saturating_mul(u32::from(ANNOUNCE_REPEATS).saturating_add(1));
        assert!(burst < schedule.announce, "the burst is over well inside the minute");
    }

    /// The trigger that makes the difference a person notices: arriving home
    /// should not mean waiting for a tick before the LAN path is tried.
    #[test]
    fn an_interface_change_announces_immediately() {
        let mut announcing = Announcing::new();
        assert!(announcing.should_announce(&addresses(&["wifi"]), false), "the first is new");
        assert!(!announcing.should_announce(&addresses(&["wifi"]), false), "then nothing changed");

        assert!(
            announcing.should_announce(&addresses(&["wifi", "ethernet"]), false),
            "a new interface announces without waiting for the tick"
        );
        assert!(
            announcing.should_announce(&addresses(&["ethernet"]), false),
            "and so does one going away"
        );
    }

    /// Multicast on Wi-Fi is unreliable enough that one announcement proves
    /// nothing, so the tick repeats even when nothing has changed.
    #[test]
    fn the_tick_announces_even_when_nothing_changed() {
        let mut announcing = Announcing::new();
        assert!(announcing.should_announce(&addresses(&["wifi"]), false));

        assert!(!announcing.should_announce(&addresses(&["wifi"]), false));
        assert!(announcing.should_announce(&addresses(&["wifi"]), true), "the tick repeats it");
    }

    #[test]
    fn losing_every_interface_is_a_change() {
        let mut announcing = Announcing::new();
        assert!(announcing.should_announce(&addresses(&["wifi"]), false));
        assert!(announcing.should_announce(&[], false), "having no interface is news");
    }

    #[test]
    fn a_change_can_be_asked_about_without_being_recorded() {
        let mut announcing = Announcing::new();
        announcing.should_announce(&addresses(&["wifi"]), false);

        assert!(!announcing.would_change(&addresses(&["wifi"])));
        assert!(announcing.would_change(&addresses(&["ethernet"])));
        assert!(!announcing.would_change(&addresses(&["wifi"])), "asking changed nothing");
    }

    #[test]
    fn coming_back_up_announces_again() {
        let mut announcing = Announcing::new();
        assert!(announcing.should_announce(&addresses(&["wifi"]), false));
        announcing.forget();
        assert!(
            announcing.should_announce(&addresses(&["wifi"]), false),
            "the peers that heard the last announcement have forgotten it too"
        );
    }

    #[test]
    fn a_cached_endpoint_survives_an_overnight_gap() {
        // §2.6b's restore path depends on the cache being warm in the morning.
        assert!(Schedule::provisional().endpoint_cache >= Duration::from_secs(12 * 60 * 60));
    }
}

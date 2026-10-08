//! When the daemon does the things five crates left it to decide.
//!
//! `roster-sync` has no loop, `rendezvous` no publish policy, `local-discovery`
//! no announcement schedule. Each of them said so plainly and deferred here. This
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
//! announcements were most of it. [`Schedule::sync`], [`Schedule::announce`],
//! [`Schedule::press_longest`] and [`Schedule::idle`] are set from that
//! measurement, and say so where they are defined.
//!
//! The others are still argued rather than measured: `publish`, `endpoint_cache`
//! and `press`. If one of them is still unchanged after the daemon has run on a
//! real machine for a week, that is a sign nobody looked — not a sign it was
//! right.

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

    /// How often to publish to the rendezvous when nothing has changed.
    ///
    /// A publish also happens whenever the observed address set changes, which is
    /// the event that actually matters. This tick only refreshes a record that
    /// would otherwise look stale to a peer that has never seen this device.
    pub publish: Duration,

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

    /// How long a cached endpoint is worth trying before the rendezvous.
    ///
    /// §2.6b puts the restore path under 500 ms using cached endpoints without
    /// waiting for the rendezvous, so this has to outlive an ordinary overnight
    /// gap. A stale entry costs one failed attempt; a missing one costs a
    /// round trip to a server that may not be reachable.
    pub endpoint_cache: Duration,

    /// How soon to try a member that is owed something this device signed.
    ///
    /// An idle network and a network carrying a revocation nobody has yet
    /// received were paced identically: both dialled on [`Self::sync`]. That is
    /// the wrong economy at both ends — a minute of exposure when a revoked
    /// device's peer comes back a moment after the revocation is signed, and a
    /// minute is also far too often to keep dialling a laptop that has been
    /// switched off for a week.
    ///
    /// So this is where pressing *starts*, and [`Pressing`] widens it back toward
    /// [`Self::sync`] as attempts go unanswered. Short, because the attempts most
    /// likely to be answered are the ones just after the event.
    pub press: Duration,
    /// The longest pressing ever waits.
    ///
    /// Pressing used to widen only to the ordinary tick, a minute, and stay
    /// there: a device switched off for a week was dialled every minute for the
    /// week, and each attempt retried a handshake on every path it knew for half
    /// a minute. Six hours is a few attempts a day for a device that is simply
    /// away, while one that comes back soon after the operation is still found
    /// within seconds.
    pub press_longest: Duration,
    /// How long a session may carry nothing before it is closed.
    ///
    /// A session is opened by the first packet that needs it, so a closed one
    /// costs the next packet a reopening: a handshake of a few kilobytes and a
    /// pause of tens to hundreds of milliseconds. An open one costs a keep-alive
    /// every three seconds each way, about 100 bytes a second, for as long as it
    /// stays open. Ten minutes keeps a session through the ordinary pauses of
    /// someone working — reading a page, thinking between commands — and closes it
    /// once they have stopped.
    pub idle: Duration,
}

impl Schedule {
    /// The provisional schedule, pending measurement.
    #[must_use]
    pub const fn provisional() -> Self {
        Self {
            sync: Duration::from_secs(60 * 60),
            publish: Duration::from_secs(15 * 60),
            announce: Duration::from_secs(60),
            endpoint_cache: Duration::from_secs(24 * 60 * 60),
            press: Duration::from_secs(2),
            press_longest: Duration::from_secs(6 * 60 * 60),
            idle: Duration::from_secs(10 * 60),
        }
    }
}

/// Decides how long to wait before pressing a member that is owed something.
///
/// Pure, and separate from the loop that sleeps, for the same reason
/// [`Publishing`] is: the interesting half is the decision, and a decision made
/// inside a `sleep` can only be tested by waiting for it.
///
/// The rule is that urgency decays. The attempts most likely to be answered are
/// the ones immediately after an operation is signed — a device that is going to
/// come back usually comes back soon — so pressing starts short and doubles until
/// it reaches [`Schedule::press_longest`], six hours. A device that has been off
/// for a week is then tried a few times a day, rather than every two seconds — or
/// every minute — for a week.
///
/// It starts short again when the amount owed **grows**, because that is a new
/// event rather than a continuation of the old wait. A person who revokes a
/// second device should not have that revocation paced by how long the first one
/// has been waiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pressing {
    /// What the next press will wait.
    interval: Duration,
    /// How much was owed when this was last asked.
    owed: usize,
}

impl Pressing {
    /// Nothing pressed yet.
    #[must_use]
    pub const fn new(start: Duration) -> Self {
        Self { interval: start, owed: 0 }
    }

    /// How long to wait, given how much is currently owed.
    ///
    /// `owed` is the number of (operation, device) pairs outstanding toward
    /// members with no open session — the work pressing exists to finish. With
    /// nothing owed the answer is the ordinary tick, and the next press starts
    /// short again.
    pub fn next(&mut self, owed: usize, schedule: &Schedule) -> Duration {
        if owed == 0 {
            *self = Self::new(schedule.press);
            return schedule.sync;
        }

        if owed > self.owed {
            self.interval = schedule.press;
        }
        self.owed = owed;

        let waiting = self.interval.min(schedule.press_longest);
        self.interval = self.interval.saturating_mul(2).min(schedule.press_longest);
        waiting
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

/// Decides when a rendezvous publish is worth making.
///
/// The rule is that a publish follows a change in what this device believes it is
/// reachable at, not the passage of time. Publishing an unchanged record teaches
/// the rendezvous nothing and tells anyone watching it that this device is
/// switched on, which is a metadata leak for no gain.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Publishing {
    /// The addresses published last time, in the order they were given.
    last: Option<Vec<String>>,
}

impl Publishing {
    /// Nothing published yet.
    #[must_use]
    pub const fn new() -> Self {
        Self { last: None }
    }

    /// Whether to publish, given what is observed now.
    ///
    /// `refresh_due` carries the slow tick: a record that has not changed still
    /// gets refreshed eventually, so a peer that has never seen this device does
    /// not find an ancient one.
    pub fn should_publish(&mut self, observed: &[String], refresh_due: bool) -> bool {
        let changed = match &self.last {
            None => true,
            Some(previous) => previous.as_slice() != observed,
        };

        if changed || refresh_due {
            self.last = Some(observed.to_vec());
            true
        } else {
            false
        }
    }

    /// Forgets what was published, so the next observation counts as a change.
    ///
    /// Used when the network comes up: what was true before it went down is not
    /// evidence about now.
    pub fn forget(&mut self) {
        self.last = None;
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
    /// [`crate::limits::INTERFACE_RECHECK`] each: thirty seconds. Late enough to
    /// let a flicker pass, early enough that a device that really moved catches
    /// up within a minute.
    pub const STEADY: u32 = 6;

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

    /// Publishing follows a change in what is observed, not the clock.
    #[test]
    fn a_changed_address_set_is_published() {
        let mut publishing = Publishing::new();

        assert!(publishing.should_publish(&addresses(&["a"]), false), "the first is always new");
        assert!(publishing.should_publish(&addresses(&["a", "b"]), false), "a change publishes");
        assert!(publishing.should_publish(&addresses(&["b"]), false), "so does a removal");
    }

    #[test]
    fn an_unchanged_address_set_is_not_published() {
        let mut publishing = Publishing::new();
        assert!(publishing.should_publish(&addresses(&["a", "b"]), false));

        assert!(
            !publishing.should_publish(&addresses(&["a", "b"]), false),
            "republishing the same record teaches nobody anything and leaks that this device is on"
        );
        assert!(!publishing.should_publish(&addresses(&["a", "b"]), false));
    }

    #[test]
    fn an_unchanged_set_is_still_refreshed_eventually() {
        let mut publishing = Publishing::new();
        assert!(publishing.should_publish(&addresses(&["a"]), false));
        assert!(!publishing.should_publish(&addresses(&["a"]), false));
        assert!(publishing.should_publish(&addresses(&["a"]), true), "the slow tick refreshes");
    }

    #[test]
    fn ordering_counts_as_a_change_rather_than_being_guessed_at() {
        let mut publishing = Publishing::new();
        assert!(publishing.should_publish(&addresses(&["a", "b"]), false));
        assert!(
            publishing.should_publish(&addresses(&["b", "a"]), false),
            "the transport orders these; second-guessing it here would hide a real change"
        );
    }

    #[test]
    fn losing_every_address_is_a_change() {
        let mut publishing = Publishing::new();
        assert!(publishing.should_publish(&addresses(&["a"]), false));
        assert!(publishing.should_publish(&[], false), "having no address is news");
    }

    #[test]
    fn coming_back_up_forgets_what_was_true_before() {
        let mut publishing = Publishing::new();
        assert!(publishing.should_publish(&addresses(&["a"]), false));
        publishing.forget();
        assert!(
            publishing.should_publish(&addresses(&["a"]), false),
            "what was true before the network went down is not evidence about now"
        );
    }

    /// The numbers are provisional, and the point is that they are together.
    #[test]
    fn the_schedule_is_in_one_place() {
        let schedule = Schedule::provisional();
        assert!(schedule.announce < schedule.sync, "announcing is cheap and unreliable");
        // Not ordered against publishing any more: a published record is a
        // device's own address, refreshed on a period because nothing else
        // refreshes it, while operations are pushed the moment they are admitted
        // and the sync tick only catches a push that was lost.
        assert!(schedule.sync >= Duration::from_secs(60 * 60), "a safety net, not the transport");
        assert!(schedule.publish < schedule.endpoint_cache, "a cached endpoint outlives a record");
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

    /// Urgency is the point: a revocation must not be paced like an idle
    /// network.
    #[test]
    fn pressing_starts_sooner_than_the_ordinary_tick() {
        let schedule = Schedule::provisional();
        let mut pressing = Pressing::new(schedule.press);
        assert!(
            pressing.next(1, &schedule) < schedule.sync,
            "the first attempt after signing comes sooner than the idle tick"
        );
    }

    /// And decays, so a device that has been switched off for a week is not
    /// dialled every two seconds — or every minute — for a week.
    #[test]
    fn pressing_widens_to_hours() {
        let schedule = Schedule::provisional();
        let mut pressing = Pressing::new(schedule.press);

        let mut previous = pressing.next(1, &schedule);
        let mut widened = false;
        for _ in 0..30u32 {
            let waiting = pressing.next(1, &schedule);
            assert!(waiting >= previous, "the interval never narrows while the wait continues");
            assert!(waiting <= schedule.press_longest, "and never exceeds six hours");
            widened |= waiting > previous;
            previous = waiting;
        }
        assert!(widened, "it widens rather than repeating");
        assert!(previous > Duration::from_secs(60), "past a minute");
        assert_eq!(previous, schedule.press_longest, "settling at six hours");
    }

    /// A second revocation is a new event, not a continuation of the first
    /// one's wait.
    #[test]
    fn something_newly_owed_starts_short_again() {
        let schedule = Schedule::provisional();
        let mut pressing = Pressing::new(schedule.press);

        for _ in 0..10u32 {
            pressing.next(1, &schedule);
        }
        assert_eq!(
            pressing.next(2, &schedule),
            schedule.press,
            "more owed than before resets the urgency"
        );
    }

    /// Nothing owed is not a wait at all.
    #[test]
    fn nothing_owed_falls_back_to_the_ordinary_tick() {
        let schedule = Schedule::provisional();
        let mut pressing = Pressing::new(schedule.press);

        for _ in 0..10u32 {
            pressing.next(1, &schedule);
        }
        assert_eq!(pressing.next(0, &schedule), schedule.sync);
        assert_eq!(
            pressing.next(1, &schedule),
            schedule.press,
            "and the next thing owed is pressed from the start"
        );
    }
}

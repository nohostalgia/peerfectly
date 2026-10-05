//! Attesting that the roster up to here is this, so that a device somewhere else
//! can tell how old its own is.
//!
//! # Why the daemon has to be the one doing it
//!
//! Everything a snapshot needs already existed. `roster` can build one, sign one,
//! verify one and measure freshness against one; `roster-sync` already carries
//! one, and already refuses a sequence that does not advance. What was missing
//! was anything that ever *made* one — the only call to `sign_snapshot` outside
//! the test vectors was in a test.
//!
//! The security review called this finding F-04. Freshness is measured
//! from the last accepted snapshot, so with no snapshot there is nothing to
//! measure from, and a device holds its roster as current for ever. A revocation
//! signed on one machine binds nowhere else until the two machines meet, and
//! nothing anywhere puts a limit on how long that may be.
//!
//! # A snapshot is not an operation
//!
//! It is not appended to the log, never named as a parent, and takes no part in
//! merge. Signing one changes no derived state on any device — it dates the state
//! rather than altering it. So this module can run on a timer without any of the
//! questions that would come with a daemon that signed *operations* on a timer.
//!
//! # Only an admin, and only over what it holds
//!
//! The roster refuses a snapshot signed by a device it does not name as an admin,
//! so this could be left to fail there. It is checked here as well, because the
//! failure this prevents is not a refusal — it is a member's daemon asking a
//! phone's keystore for a signature every few minutes, and raising a lock prompt
//! each time, for a snapshot that will be thrown away.

use identity::NodeIdentity;
use roster::id::DeviceId;
use roster::roster::Roster;
use roster::snapshot::Snapshot;
use roster::state::RosterState;

/// Signs a snapshot over the heads this roster currently holds.
///
/// Returns the signed bytes, ready to be offered to a roster — this one's or a
/// peer's. Offering it here is the caller's to do: what is signed and what is
/// accepted are two acts, and a caller that failed to accept its own snapshot
/// should hear about it rather than have it happen invisibly.
///
/// # Errors
///
/// When this device is not an admin of the network, when the roster has no state
/// to attest to, or when signing is declined or fails.
pub fn sign_over_heads(roster: &Roster, identity: &NodeIdentity) -> Result<Vec<u8>, String> {
    let body = body_over_heads(roster, identity)?;
    identity.sign_snapshot(&body).map_err(|cause| cause.to_string())
}

/// The snapshot this node would sign, up to but not including its signature.
///
/// Separate from [`sign_over_heads`] because on some devices the act stops here:
/// the signing key is somewhere this process cannot reach, and what happens next
/// is that somebody else signs these bytes. Everything that decides what a
/// snapshot says is above that line and happens either way.
///
/// # Errors
///
/// When this device is not an admin, when the roster has no heads, or when the
/// body is not one the roster would accept.
pub fn body_over_heads(roster: &Roster, identity: &NodeIdentity) -> Result<Snapshot, String> {
    let state = roster.state().map_err(|cause| cause.to_string())?;
    if !state.is_admin(&identity.device_id()) {
        return Err(
            "this device is not an admin of that network, so it attests to nothing".to_owned()
        );
    }

    let heads = roster.heads();
    if heads.is_empty() {
        return Err("that roster has no heads, so there is nothing to attest to".to_owned());
    }

    // Positionally matched with `heads`, and taken from this node's own graph.
    // A snapshot whose depths were guessed would resolve concurrent renames
    // differently from a node that kept its history — a fork that shows up only
    // when two admins rename one device at once.
    let dag = roster.dag();
    let mut depths = Vec::with_capacity(heads.len());
    for head in &heads {
        let index = dag
            .position(head)
            .ok_or_else(|| "a head of this roster is not in its own graph".to_owned())?;
        depths.push(dag.depth(index));
    }

    // The heads cover everything, so the state they imply is the state this node
    // already derived. Deriving it again over a rebuilt graph would be the same
    // answer reached the long way.
    let body = Snapshot::new(
        next_sequence(roster),
        state.to_bytes(),
        heads,
        depths,
        identity.signing_key().key_id(),
        state.network,
    )
    .map_err(|cause| cause.to_string())?;

    Ok(body)
}

/// The snapshot a batch should end with, if the network will be owed one once
/// `cores` are in.
///
/// Built over [`Roster::preview`], so the operations it covers have not been
/// signed yet: the whole act — operations and snapshot — is prepared first, shown
/// to a person together, and signed together. The body is ordinary; the roster
/// that is later offered it derives the covered state from operations it has
/// verified, and a body that disagreed would be refused rather than trusted.
///
/// `None` when no snapshot is due, including when the act leaves this device no
/// admin.
///
/// # Errors
///
/// When the operations cannot be previewed over this roster.
pub fn after(
    roster: &Roster,
    cores: &[roster::types::OperationCore],
    identity: &NodeIdentity,
    now: u64,
) -> Result<Option<Snapshot>, String> {
    let preview = roster.preview(cores).map_err(|cause| cause.to_string())?;
    if !due_over(roster, &preview.state, identity, now) {
        return Ok(None);
    }
    body_over_preview(roster, preview, identity).map(Some)
}

/// A snapshot body over a preview of operations not yet signed.
///
/// The same body [`body_over_heads`] would build once those operations were in:
/// the sequence follows what `roster` holds, and the state, heads and depths are
/// the preview's.
///
/// # Errors
///
/// When the preview has no heads, or the body is not one the roster would take.
pub fn body_over_preview(
    roster: &Roster,
    preview: roster::roster::Preview,
    identity: &NodeIdentity,
) -> Result<Snapshot, String> {
    if !preview.state.is_admin(&identity.device_id()) {
        return Err(
            "this device is not an admin of that network, so it attests to nothing".to_owned()
        );
    }
    if preview.heads.is_empty() {
        return Err("that roster has no heads, so there is nothing to attest to".to_owned());
    }
    Snapshot::new(
        next_sequence(roster),
        preview.state.to_bytes(),
        preview.heads,
        preview.depths,
        identity.signing_key().key_id(),
        preview.state.network,
    )
    .map_err(|cause| cause.to_string())
}

/// Why a device cannot confirm a network's roster.
///
/// Three states of [`roster::roster::Freshness`] mean the same thing to a caller
/// deciding what to act on — the roster cannot be confirmed — and different
/// things to a person deciding what to do about it. So they are kept apart here
/// and collapsed only where the decision is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cautious {
    /// The network's window has passed with nothing fresher accepted.
    Stale,
    /// No snapshot has ever been accepted for this network.
    ///
    /// A network founded by this build has one from its first moment and a device
    /// that joined one was given it, so this means neither happened: a founding
    /// whose second signature was declined, a delivery that carried none, or a
    /// network older than snapshots being signed at all.
    NeverAttested,
    /// The clock moved, so elapsed time cannot be read from it.
    ///
    /// A correction and tampering look identical from in here, and only one is
    /// benign. Treated as a roster that cannot be confirmed for that reason: the
    /// other reading — that no time has passed — is the one an attacker wants.
    ClockMoved,
}

impl Cautious {
    /// What this device should say about it, and what a person can do.
    #[must_use]
    pub const fn because(self) -> &'static str {
        match self {
            Self::Stale => {
                "this device has not been able to confirm that network's roster within the time the network allows. Until it reaches an administrator, it will not carry traffic to devices that are not administrators."
            }
            Self::NeverAttested => {
                "this device has never accepted a snapshot for that network, so it has nothing to measure its roster against. Until it reaches an administrator, it will not carry traffic to devices that are not administrators."
            }
            Self::ClockMoved => {
                "this device's clock has moved backwards, so it cannot tell how old that network's roster is. Until it reaches an administrator, it will not carry traffic to devices that are not administrators."
            }
        }
    }
}

/// Whether this roster can be confirmed, and why not when it cannot.
///
/// `Unknown` from a roster that derives no state is not cautious: that is a
/// device holding nothing, which has no network to be careful about.
#[must_use]
pub fn cautious(roster: &mut Roster) -> Option<Cautious> {
    if roster.state().is_err() {
        return None;
    }
    match roster.freshness() {
        roster::roster::Freshness::Fresh => None,
        roster::roster::Freshness::Stale => Some(Cautious::Stale),
        roster::roster::Freshness::Unknown => Some(Cautious::NeverAttested),
        roster::roster::Freshness::ClockWentBackwards => Some(Cautious::ClockMoved),
    }
}

/// Why a session with this peer must be refused, if it must.
///
/// **This is what bounds the revocation window.** A device that has not been able
/// to confirm its roster for longer than the network allows stops honouring a
/// membership it can no longer confirm, rather than honouring it for ever. A
/// revoked device that no honest peer will talk to arrives at this on its own,
/// which is the case no amount of delivery can fix.
///
/// Administrators are the exception, because an administrator is the only thing
/// that ends the condition: it is what signs a fresher snapshot. Refusing them
/// too would make this absorbing — a device that entered it could never leave.
///
/// The roster's answer, asked here rather than in the node: what a peer is, is
/// the roster's to say, and the node holds no second opinion about it.
#[must_use]
pub fn refused(state: &RosterState, peer: &DeviceId, why: Cautious) -> Option<String> {
    if state.is_admin(peer) {
        return None;
    }
    Some(format!("{peer:?} is not an administrator of that network, and {}", why.because()))
}

/// The devices a roster names as administrators.
///
/// Asked here rather than in the node for the same reason [`refused`] is: what a
/// device is, is the roster's to say, and the node holds no second opinion about
/// it. Gathered once and kept, because the answer is needed on the path that
/// carries every packet and deriving it there would pay for something that
/// changes at most once a reconciliation.
#[must_use]
pub fn admins_of(state: &RosterState) -> std::collections::BTreeSet<DeviceId> {
    state
        .devices
        .values()
        .filter(|record| state.is_admin(&record.id))
        .map(|record| record.id)
        .collect()
}

/// How much of a network's window may pass before an admin signs again.
///
/// A quarter. The number that matters is not this one but the gap it leaves: a
/// device has the remaining three quarters of the window to meet an admin and
/// take the fresher snapshot before its own runs out. Signing only once a window
/// had passed would mean every other device went stale first, which is the
/// failure this is arranged to avoid.
const SHARE_OF_THE_WINDOW: u64 = 4;

/// Whether this device should sign a fresh snapshot for this network now.
///
/// False for a device the roster does not name as an admin — which is most of
/// them, and is checked before anything else because on a phone the next step
/// asks for the lock.
#[must_use]
pub fn due(roster: &Roster, identity: &NodeIdentity, now: u64) -> bool {
    let Ok(state) = roster.state() else { return false };
    due_over(roster, &state, identity, now)
}

/// Whether a snapshot is due, judged against `state` rather than the roster's
/// own — the state a batch's operations *will* make, once they are in.
///
/// Why it matters: an act that demotes or revokes this device leaves it no
/// admin, and a snapshot it then signed would be refused by every roster that
/// took the act. The schedule itself is the roster's; only who is admin is read
/// from `state`.
#[must_use]
pub fn due_over(roster: &Roster, state: &RosterState, identity: &NodeIdentity, now: u64) -> bool {
    if !state.is_admin(&identity.device_id()) {
        return false;
    }
    // Nothing accepted yet: a founding whose second signature was declined, or a
    // network that predates snapshots being signed at all.
    let Some(received_at) = roster.snapshot_received_at() else { return true };
    // A receipt in the future is a clock that moved. Signing again is the safe
    // answer: what is written afterwards is dated by the same clock as the
    // reading, so the pair agree again.
    if now < received_at {
        return true;
    }
    let window = state.params.snapshot_window;
    now.saturating_sub(received_at) > window.checked_div(SHARE_OF_THE_WINDOW).unwrap_or(window)
}

/// The sequence a snapshot signed now must carry.
///
/// One past whatever this node holds. The rule the roster enforces is that the
/// number advances; starting at one when nothing is held keeps the first
/// snapshot of a network at a number a person reading a log would expect.
fn next_sequence(roster: &Roster) -> u64 {
    roster.snapshot().map_or(1, |held| held.body().seq.saturating_add(1))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use identity::NodeIdentity;
    use roster::roster::{Freshness, Roster};
    use roster::types::{NetworkParams, OperationBody, OperationCore, Role};

    use super::*;

    /// A network with one admin, the identity that founded it, and the bytes it
    /// was founded with — so a second roster can be built from the same history.
    fn founded_with_bytes() -> (Roster, NodeIdentity, Vec<u8>) {
        let founder = NodeIdentity::generate().expect("generates");
        let params =
            NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 2_592_000)
                .expect("valid");
        let genesis = OperationCore::new(
            1,
            founder.signing_key().algorithm(),
            OperationBody::CreateNetwork {
                device: founder.device_spec("laptop", Role::Admin, true, vec![]).expect("spec"),
                params,
            },
            vec![],
            founder.signing_key().key_id(),
            roster::id::NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed");
        let bytes = founder.sign_operation(&genesis).expect("signs");

        let mut roster = Roster::new();
        assert!(roster.offer_bytes(&bytes).is_accepted(), "the genesis is accepted");
        (roster, founder, bytes)
    }

    /// The same, for tests that do not need the bytes.
    fn founded() -> (Roster, NodeIdentity) {
        let (roster, founder, _bytes) = founded_with_bytes();
        (roster, founder)
    }

    /// The point of the module: an admin can attest, and its own roster believes
    /// it. Everything else here is about what must not happen.
    #[test]
    fn an_admin_signs_a_snapshot_its_own_roster_accepts() {
        let (mut roster, founder) = founded();

        let bytes = sign_over_heads(&roster, &founder).expect("an admin signs");
        let admission = roster.offer_snapshot(&bytes);

        assert!(admission.is_accepted(), "its own roster accepts it: {admission:?}");
        assert_eq!(
            Freshness::Unknown,
            roster.freshness(),
            "and a snapshot dates nothing: freshness is what an attestation is for"
        );

        let dated = crate::attesting::sign_over_heads(&roster, &founder).expect("attests");
        assert!(roster.offer_attestation(&dated).is_accepted());
        assert_eq!(Freshness::Fresh, roster.freshness(), "now it is dated");
    }

    /// Refused here rather than left to the roster, because the cost of leaving
    /// it is a lock prompt on a phone for a signature nobody will keep.
    #[test]
    fn a_device_that_is_not_an_admin_signs_nothing() {
        let (roster, _founder) = founded();
        let stranger = NodeIdentity::generate().expect("generates");

        let refusal =
            sign_over_heads(&roster, &stranger).expect_err("a stranger attests to nothing");

        assert!(refusal.contains("not an admin"), "and says why: {refusal}");
    }

    /// The sequence advances, because a roster refuses one that does not — and a
    /// second snapshot that could never be accepted is worse than none.
    #[test]
    fn a_second_snapshot_advances_the_sequence() {
        let (mut roster, founder) = founded();

        let first = sign_over_heads(&roster, &founder).expect("signs");
        assert!(roster.offer_snapshot(&first).is_accepted());
        let second = sign_over_heads(&roster, &founder).expect("signs again");
        let admission = roster.offer_snapshot(&second);

        assert!(admission.is_accepted(), "the second is accepted too: {admission:?}");
        assert_eq!(Some(2), roster.snapshot().map(|held| held.body().seq), "and it is the second");
    }

    /// The window a network is founded with, for reading the arithmetic below.
    fn window_of(roster: &Roster) -> u64 {
        roster.state().expect("a network").params.snapshot_window
    }

    /// An admin with nothing accepted signs at once. A founding whose second
    /// signature was declined leaves exactly this, and it must not wait a
    /// quarter of a month to be put right.
    #[test]
    fn an_admin_holding_no_snapshot_is_due_at_once() {
        let (roster, founder) = founded();

        assert!(due(&roster, &founder, crate::state::wall_seconds()), "there is nothing to be old");
    }

    /// The cadence, and the gap it leaves. Signing only once the window had
    /// passed would mean every other device went stale before the fresher one
    /// existed.
    #[test]
    fn an_admin_signs_again_well_before_its_own_roster_would_go_stale() {
        let (mut roster, founder) = founded();
        let window = window_of(&roster);
        let bytes = sign_over_heads(&roster, &founder).expect("signs");
        assert!(roster.offer_snapshot(&bytes).is_accepted());
        // A snapshot dates nothing; freshness comes from an attestation.
        let dated = crate::attesting::sign_over_heads(&roster, &founder).expect("attests");
        assert!(roster.offer_attestation(&dated).is_accepted());
        let accepted_at = roster.snapshot_received_at().expect("dated");

        assert!(!due(&roster, &founder, accepted_at), "not the moment it was accepted");
        assert!(
            !due(&roster, &founder, accepted_at.saturating_add(window / 8)),
            "nor a while after"
        );
        assert!(
            due(&roster, &founder, accepted_at.saturating_add(window / 2)),
            "but well before the window is out"
        );

        // The property that matters: whatever the cadence is, a device taking the
        // fresher snapshot has most of the window left to do it in.
        let signs_again_after = window / SHARE_OF_THE_WINDOW;
        assert!(
            signs_again_after < window,
            "an admin that waited a whole window would let every other device go stale first"
        );
    }

    /// Checked before anything reaches a key, because on a phone the next step
    /// asks for the lock — and a member would be asked for ever, for nothing.
    #[test]
    fn a_member_is_never_due_however_long_it_waits() {
        let (roster, _founder) = founded();
        let member = NodeIdentity::generate().expect("generates");
        let window = window_of(&roster);

        for elapsed in [0, window, window.saturating_mul(100)] {
            assert!(
                !due(&roster, &member, crate::state::wall_seconds().saturating_add(elapsed)),
                "a device that is not an admin attests to nothing, ever"
            );
        }
    }

    /// A clock that moved backwards is answered by signing again, so that what is
    /// written afterwards is dated by the same clock as the reading.
    #[test]
    fn a_receipt_in_the_future_is_due() {
        let (mut roster, founder) = founded();
        let bytes = sign_over_heads(&roster, &founder).expect("signs");

        // Dated explicitly, because what is under test is a receipt the clock
        // cannot have produced — which is what a clock that moved leaves behind.
        let dated_at = 10_000;
        assert!(roster.restore_snapshot(&bytes, dated_at).is_accepted());

        assert!(due(&roster, &founder, dated_at.saturating_sub(60)), "the clock moved");
    }

    /// **A snapshot over a preview is the one signing would have made.** The
    /// member's admission is previewed, a snapshot is built over the preview, and
    /// it must equal the one built over a roster that really took the admission —
    /// and be accepted by that roster once signed.
    #[test]
    fn a_snapshot_over_a_preview_is_the_one_signing_makes() {
        let (roster, founder, genesis) = founded_with_bytes();
        let member = NodeIdentity::generate().expect("generates");
        let state = roster.state().expect("a network");
        let add = roster::types::OperationCore::new(
            2,
            founder.signing_key().algorithm(),
            roster::types::OperationBody::AddDevice(
                member.device_spec("laptop", Role::Member, false, vec![]).expect("spec"),
            ),
            roster.heads(),
            founder.signing_key().key_id(),
            state.network,
        )
        .expect("well-formed");

        let previewed = after(&roster, core::slice::from_ref(&add), &founder, 0)
            .expect("previews")
            .expect("nothing is held, so one is due");

        let mut signed = Roster::new();
        assert!(signed.offer_bytes(&genesis).is_accepted());
        let added = founder.sign_operation(&add).expect("signs");
        assert!(signed.offer_bytes(&added).is_accepted());
        assert_eq!(body_over_heads(&signed, &founder).expect("a body"), previewed);

        let bytes = founder.sign_snapshot(&previewed).expect("signs");
        assert!(signed.offer_snapshot(&bytes).is_accepted(), "and that roster takes it");
    }

    /// **An act that leaves this device no admin is owed no snapshot by it.**
    /// Judged on the state the batch will make, not on the roster as it stands:
    /// signing one would be signing something every roster that took the act
    /// would refuse.
    #[test]
    fn a_snapshot_is_due_only_where_the_previewed_state_keeps_this_device_admin() {
        let (roster, founder, _genesis) = founded_with_bytes();
        let now_admin = roster.state().expect("a network");
        assert!(due_over(&roster, &now_admin, &founder, 0), "admin, and nothing held");

        let mut no_longer = now_admin;
        no_longer.devices.retain(|id, _| *id != founder.device_id());
        assert!(
            !due_over(&roster, &no_longer, &founder, 0),
            "the roster still names it admin, and the state after the act does not"
        );
    }

    /// A network with an admin and an ordinary member: the roster, the admin's
    /// identity, the member's id, and the operations it was built from.
    fn with_a_member() -> (Roster, NodeIdentity, DeviceId, Vec<Vec<u8>>) {
        let (mut roster, founder, genesis) = founded_with_bytes();
        let member = NodeIdentity::generate().expect("generates");
        let state = roster.state().expect("a network");
        let add = roster::types::OperationCore::new(
            2,
            founder.signing_key().algorithm(),
            roster::types::OperationBody::AddDevice(
                member
                    .device_spec("laptop", roster::types::Role::Member, false, vec![])
                    .expect("spec"),
            ),
            roster.heads(),
            founder.signing_key().key_id(),
            state.network,
        )
        .expect("well-formed");
        let bytes = founder.sign_operation(&add).expect("signs");
        assert!(roster.offer_bytes(&bytes).is_accepted(), "the member is admitted");
        let id = member.device_id();
        (roster, founder, id, vec![genesis, bytes])
    }

    /// The same history, on the clock a daemon uses.
    fn on_the_wall_clock(operations: &[Vec<u8>]) -> Roster {
        let mut roster = Roster::with_clock(Box::new(crate::state::WallClock));
        for operation in operations {
            assert!(roster.offer_bytes(operation).is_accepted(), "the history replays");
        }
        roster
    }

    /// A roster that can be confirmed refuses nobody. Everything below is about
    /// what happens when it cannot be.
    #[test]
    fn a_fresh_roster_refuses_nobody() {
        let (mut roster, founder, member, _held) = with_a_member();
        let bytes = sign_over_heads(&roster, &founder).expect("signs");
        assert!(roster.offer_snapshot(&bytes).is_accepted());
        // A snapshot dates nothing; freshness comes from an attestation.
        let dated = crate::attesting::sign_over_heads(&roster, &founder).expect("attests");
        assert!(roster.offer_attestation(&dated).is_accepted());

        assert_eq!(None, cautious(&mut roster), "there is nothing to be careful about");
        let state = roster.state().expect("a network");
        assert!(refused(&state, &member, Cautious::Stale).is_some(), "the rule bites when it does");
        assert!(refused(&state, &founder.device_id(), Cautious::Stale).is_none());
    }

    /// The exception that keeps cautious mode from being absorbing: an admin is
    /// the only thing that *signs* a fresher snapshot, so its traffic keeps
    /// flowing. Every peer is still reconciled with — that part is not a refusal
    /// at all, and is what lets any member carry the cure.
    #[test]
    fn a_stale_roster_refuses_a_member_and_admits_an_admin() {
        let (roster, founder, member, _held) = with_a_member();
        let state = roster.state().expect("a network");

        for why in [Cautious::Stale, Cautious::NeverAttested, Cautious::ClockMoved] {
            let refusal = refused(&state, &member, why).expect("a member is refused");
            assert!(
                refusal.contains("not an administrator"),
                "and the refusal says which of the two it is: {refusal}"
            );
            assert!(
                refused(&state, &founder.device_id(), why).is_none(),
                "an admin is served, or nothing could ever end it"
            );
        }
    }

    /// The three states a roster can be in that mean it cannot be confirmed.
    /// Each is reported as itself, because what a person does about them differs.
    #[test]
    fn each_reason_a_roster_cannot_be_confirmed_is_named() {
        let (mut roster, founder, _member, held) = with_a_member();
        assert_eq!(
            Some(Cautious::NeverAttested),
            cautious(&mut roster),
            "nothing has ever been accepted for it"
        );

        let bytes = crate::attesting::sign_over_heads(&roster, &founder).expect("attests");
        let window = roster.state().expect("a network").params.snapshot_window;
        let now = crate::state::wall_seconds();

        // A roster of its own for each, because the sequence rule refuses an
        // attestation that does not advance the number already held.
        let mut just_now = on_the_wall_clock(&held);
        assert!(just_now.restore_attestation(&bytes, now).is_accepted());
        assert_eq!(None, cautious(&mut just_now), "accepted a moment ago");

        let mut long_ago = on_the_wall_clock(&held);
        assert!(
            long_ago
                .restore_attestation(&bytes, now.saturating_sub(window.saturating_add(60)))
                .is_accepted()
        );
        assert_eq!(Some(Cautious::Stale), cautious(&mut long_ago), "the window has passed");

        let mut ahead = on_the_wall_clock(&held);
        assert!(ahead.restore_attestation(&bytes, now.saturating_add(86_400)).is_accepted());
        assert_eq!(
            Some(Cautious::ClockMoved),
            cautious(&mut ahead),
            "received in a future this clock has not reached"
        );
    }

    /// Cautious mode must not be absorbing. A device that reached an admin and
    /// took a fresher snapshot serves its members again.
    #[test]
    fn a_fresher_snapshot_ends_it() {
        let (roster, founder, _member, held) = with_a_member();
        let window = roster.state().expect("a network").params.snapshot_window;
        let now = crate::state::wall_seconds();

        let first = crate::attesting::sign_over_heads(&roster, &founder).expect("attests");
        let mut device = on_the_wall_clock(&held);
        assert!(
            device
                .restore_attestation(&first, now.saturating_sub(window.saturating_add(60)))
                .is_accepted()
        );
        assert_eq!(Some(Cautious::Stale), cautious(&mut device), "out of touch too long");

        // What reconciling with an admin delivers: the next attestation in
        // sequence, sent because the admin's period passed or its heads moved.
        let mut admin = on_the_wall_clock(&held);
        assert!(admin.restore_attestation(&first, now).is_accepted());
        let fresher = crate::attesting::sign_over_heads(&admin, &founder).expect("attests again");
        assert!(device.offer_attestation(&fresher).is_accepted(), "and the device takes it");

        assert_eq!(None, cautious(&mut device), "and serves its members again");
    }

    /// A device holds several networks, each with its own roster, its own window
    /// and its own admins. Being unable to confirm one says nothing about another.
    #[test]
    fn one_network_being_cautious_says_nothing_about_another() {
        let (roster, founder, _member, held) = with_a_member();
        let window = roster.state().expect("a network").params.snapshot_window;
        let now = crate::state::wall_seconds();
        let bytes = crate::attesting::sign_over_heads(&roster, &founder).expect("attests");

        let mut casa = on_the_wall_clock(&held);
        assert!(
            casa.restore_attestation(&bytes, now.saturating_sub(window.saturating_add(60)))
                .is_accepted()
        );
        let mut lavoro = on_the_wall_clock(&held);
        assert!(lavoro.restore_attestation(&bytes, now).is_accepted());

        assert_eq!(Some(Cautious::Stale), cautious(&mut casa));
        assert_eq!(None, cautious(&mut lavoro), "and the other is untouched");
    }

    /// A liveness opinion cannot move the roster. Two devices holding the same
    /// operations and the same snapshot derive the same members and the same
    /// admins, whatever either of them is willing to act on.
    #[test]
    fn being_cautious_changes_no_derived_state() {
        let (roster, founder, member, held) = with_a_member();
        let window = roster.state().expect("a network").params.snapshot_window;
        let now = crate::state::wall_seconds();
        let bytes = crate::attesting::sign_over_heads(&roster, &founder).expect("attests");

        let mut careful = on_the_wall_clock(&held);
        assert!(
            careful
                .restore_attestation(&bytes, now.saturating_sub(window.saturating_add(60)))
                .is_accepted()
        );
        let mut ordinary = on_the_wall_clock(&held);
        assert!(ordinary.restore_attestation(&bytes, now).is_accepted());

        assert!(cautious(&mut careful).is_some());
        assert!(cautious(&mut ordinary).is_none());

        let one = careful.state().expect("derives");
        let other = ordinary.state().expect("derives");
        assert_eq!(one.to_bytes(), other.to_bytes(), "the same roster, byte for byte");
        assert_eq!(one.is_admin(&founder.device_id()), other.is_admin(&founder.device_id()));
        assert!(one.devices.contains_key(&member), "the member is a member of both");
    }

    /// The admins are gathered once and kept, because the packet path asks this
    /// question of every packet and deriving the roster there would pay for an
    /// answer that changes at most once a reconciliation.
    #[test]
    fn the_administrators_are_gathered_from_the_roster() {
        let (roster, founder, member, _held) = with_a_member();
        let state = roster.state().expect("a network");

        let admins = admins_of(&state);

        assert!(admins.contains(&founder.device_id()), "the founder administers it");
        assert!(!admins.contains(&member), "and an ordinary member does not");
        assert_eq!(1, admins.len());
    }

    /// A device holding nothing is not cautious.    /// A device holding nothing is not cautious. There is no network to be
    /// careful about, and saying otherwise would make every daemon that has
    /// never joined one refuse peers it does not have.
    #[test]
    fn a_device_holding_no_network_is_not_cautious() {
        let mut nothing = Roster::new();

        assert_eq!(None, cautious(&mut nothing), "there is no roster to be old");
    }

    /// A phone's signing key lives in the keystore and every use of it asks for    /// A phone's signing key lives in the keystore and every use of it asks for
    /// the lock. The recurring path must therefore never reach one — a prompt a
    /// person did not ask for, arriving repeatedly, is a worse product than a
    /// roster a few days older than it could be.
    ///
    /// A source check rather than a behavioural one, because what is being
    /// asserted is that a path does *not* exist. The two names are near enough
    /// alike that the wrong one could be called without anybody noticing, and
    /// the failure would only show on a real phone.
    #[test]
    fn the_recurring_path_never_reaches_a_key_held_elsewhere() {
        let node = crate::code_of(include_str!("node.rs"));
        let service = crate::code_of(include_str!("service.rs"));

        assert!(
            node.contains("pub(crate) async fn attest_unattended(&self)"),
            "the unattended path exists under its own name"
        );
        assert!(
            node.contains("if self.identity.signing_key().custodian().is_some() {")
                && node.contains("return;"),
            "and it stops before signing when the key is held elsewhere"
        );
        assert!(
            service.contains("attest_unattended().await"),
            "the daemon's recurring work calls the unattended one"
        );
        assert!(
            !service.contains(
                ".attest_now().await;
        }

        let mut gathered"
            ),
            "and never the attended one from the recurring path"
        );

        // Where the attended one is called, a person has just signed something.
        assert!(
            service.contains("network.node().attest_now().await;"),
            "the attended path is reached from an admin act"
        );
    }

    /// The limit that follows is written where a person choosing their admins
    /// would read it, because it decides whether a network keeps working.
    #[test]
    fn the_android_limit_is_gone_and_the_mechanism_is_written_down() {
        let readme = include_str!("../README.md");

        // The guard used to require that the limit be *named*, because a
        // limitation nobody wrote down is one somebody walks into. It is
        // inverted rather than deleted: the limit is gone, and what removed it
        // has to be written down for the same reason.
        //
        // What is checked is the claim, not the words. The document quotes the
        // old limitation in order to say it no longer holds, which is how it
        // should be written — a guard that forbade the words would forbid
        // explaining what changed.
        assert!(
            readme.contains("The phone limit is gone"),
            "the document must say the limit is gone, not merely stop mentioning it"
        );

        assert!(readme.contains("attestation"), "the mechanism that replaced it is named");
        assert!(
            readme.contains("with nobody present"),
            "and what it does: dating a roster with nobody there"
        );
        assert!(
            readme.contains("carries no state"),
            "and what bounds it: an attestation carries no state"
        );
    }

    /// Freshness has to outlive the process, and an attestation is not in the log —
    /// so unless it is kept beside it, a restart holds none and reads `Unknown`.
    #[test]
    fn a_snapshot_kept_beside_the_log_comes_back_with_its_date() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = crate::state::Paths::under(scratch.path());
        paths.create().expect("creates");

        let (mut roster, founder) = founded();
        let bytes = sign_over_heads(&roster, &founder).expect("signs");
        assert!(roster.offer_snapshot(&bytes).is_accepted());
        // A snapshot dates nothing; freshness comes from an attestation.
        let dated = crate::attesting::sign_over_heads(&roster, &founder).expect("attests");
        assert!(roster.offer_attestation(&dated).is_accepted());

        // Written as it was accepted, a day ago on this device's wall clock.
        let a_day_ago = crate::state::wall_seconds().saturating_sub(86_400);
        crate::state::write_snapshot(&paths, &bytes, a_day_ago).expect("writes");

        let (kept, at) = crate::state::read_snapshot(&paths).expect("it comes back");
        assert_eq!(bytes, kept, "byte for byte, as it was signed");
        assert_eq!(a_day_ago, at, "with the moment it arrived, not this one");
    }

    /// The failure this prevents: a stale roster made fresh again by restarting.
    #[test]
    fn a_stale_roster_is_still_stale_after_a_restart() {
        let (mut roster, founder, genesis) = founded_with_bytes();
        let bytes = sign_over_heads(&roster, &founder).expect("signs");
        assert!(roster.offer_snapshot(&bytes).is_accepted());
        // A snapshot dates nothing; freshness comes from an attestation.
        let dated = crate::attesting::sign_over_heads(&roster, &founder).expect("attests");
        assert!(roster.offer_attestation(&dated).is_accepted());

        // The window this network was founded with, and a moment past it.
        let window = roster.state().expect("a network").params.snapshot_window;
        let long_ago = crate::state::wall_seconds().saturating_sub(window.saturating_add(60));

        // A fresh process: the log replayed, on the clock a daemon uses, and what
        // was kept beside it restored with the date it was kept under.
        let mut restarted = Roster::with_clock(Box::new(crate::state::WallClock));
        assert!(restarted.offer_bytes(&genesis).is_accepted(), "the log replays");
        assert!(restarted.restore_snapshot(&bytes, long_ago).is_accepted());
        // The attestation too, with the date it was kept under — which is the
        // whole of what makes freshness outlive the process.
        assert!(restarted.restore_attestation(&dated, long_ago).is_accepted());

        assert_eq!(
            Freshness::Stale,
            restarted.freshness(),
            "restarting is not a way out of a roster this device cannot confirm"
        );
    }

    /// A roster holding nothing attests to nothing, rather than signing a
    /// snapshot over an empty set that no verifier would accept.
    #[test]
    fn an_empty_roster_attests_to_nothing() {
        let roster = Roster::new();
        let identity = NodeIdentity::generate().expect("generates");

        assert!(sign_over_heads(&roster, &identity).is_err(), "there is nothing to attest to");
    }
}

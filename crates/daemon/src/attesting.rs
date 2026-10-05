//! Dating a roster, so that a device somewhere else can tell how old its own is.
//!
//! # Why this is not `snapshots`
//!
//! A snapshot carries the whole derived roster, and it is signed by the key that
//! signs operations. On a phone that key lives in the keystore and every use of
//! it raises a lock prompt, so an admin phone can only sign one where a person
//! is already present — at a founding, or in the moments after an admission.
//! `Node::attest_unattended` says as much and returns early for exactly that
//! reason.
//!
//! The consequence was written down rather than fixed: a network whose only
//! admin is a phone stays current only for as long as somebody keeps opening
//! that phone, and the remedy offered was *get a second admin on a machine that
//! stays on* — advice standing in for a mechanism.
//!
//! An attestation is the mechanism. It carries the heads and **no state**, it is
//! signed by a key that asks nobody, and it is the only thing freshness is
//! measured from. A stolen attestation key can declare a roster fresh and can do
//! nothing else, because there is nothing else the object can say.
//!
//! # Only an admin, and only over what it holds
//!
//! The roster refuses an attestation from a device it does not name as a
//! non-revoked admin, so this could be left to fail there. It is checked here as
//! well, for the same reason the snapshot module checks it: the failure being
//! prevented is not a refusal but a member's daemon producing something twice a
//! day that will be thrown away.

use identity::NodeIdentity;
use roster::attestation::{Attestation, sign_attestation};
use roster::roster::Roster;

/// How long a node may go without producing one, in seconds.
///
/// Twelve hours, a seventh of the default window: a node has to miss six in a
/// row before its peers read it as stale, and missing six is a network that is
/// genuinely not talking.
///
/// Not derived from the window, deliberately. `snapshots::due` takes a quarter
/// of it, which at seven days is forty-two hours — too slow to keep a peer fresh
/// when the window is seven days and sessions come and go.
pub const PERIOD: u64 = 12 * 60 * 60;

/// Signs an attestation over the heads this roster holds.
///
/// Returns the signed bytes, ready to be offered to a roster — this one's or a
/// peer's. Offering it here is the caller's to do, as it is for a snapshot:
/// what is signed and what is accepted are two acts.
///
/// # Errors
///
/// When this device is not an admin of the network, when the roster holds no
/// heads, or when signing fails.
pub fn sign_over_heads(roster: &Roster, identity: &NodeIdentity) -> Result<Vec<u8>, String> {
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

    let body = Attestation::new(
        next_sequence(roster),
        heads,
        identity.attestation_key().public_key().key_id(),
        state.network,
    )
    .map_err(|cause| cause.to_string())?;

    // The attestation key signs, never the signing key. That separation is the
    // whole reason the third key exists: a key that both dated a roster
    // unattended and signed operations would hand the unattended property to the
    // signing power.
    sign_attestation(&body, identity.attestation_key().signer()).map_err(|cause| cause.to_string())
}

/// Whether this node should produce one now.
///
/// True when it is an admin and either has never produced one, or the period has
/// passed since the one it holds arrived, or its clock has moved backwards — in
/// which case signing again is the safe answer, because what is written
/// afterwards is dated by the same clock as the reading.
///
/// Heads that changed are handled by the caller rather than here: that is an
/// event, and this is a question about elapsed time.
#[must_use]
pub fn due(roster: &Roster, identity: &NodeIdentity, now: u64) -> bool {
    let Ok(state) = roster.state() else { return false };
    if !state.is_admin(&identity.device_id()) {
        return false;
    }
    let Some(received_at) = roster.attestation_received_at() else { return true };
    if now < received_at {
        return true;
    }
    now.saturating_sub(received_at) > PERIOD
}

/// Whether this device may attest for this network at all.
///
/// The same question `due` asks first, without the part about elapsed time —
/// for the caller that attests because the heads moved rather than because a
/// period passed.
///
/// It lives here and not in `node` for a reason the crate enforces: what a
/// device is in a network is the roster's to decide, and `node` is checked for
/// not deciding it.
#[must_use]
pub fn may_attest(roster: &Roster, identity: &NodeIdentity) -> bool {
    roster.state().is_ok_and(|state| state.is_admin(&identity.device_id()))
}

/// The sequence an attestation signed now must carry.
///
/// One past whatever this node holds, as a snapshot's is.
fn next_sequence(roster: &Roster) -> u64 {
    roster.attestation().map_or(1, |held| held.body().seq.saturating_add(1))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use identity::NodeIdentity;
    use roster::roster::Roster;
    use roster::sign::sign_operation;
    use roster::types::{NetworkParams, OperationBody, OperationCore, Role};

    use super::*;

    /// A founded network, and the identity that founded it.
    fn founded() -> (Roster, NodeIdentity) {
        let founder = NodeIdentity::generate().expect("generates");
        let params = NetworkParams::new(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            "home.internal",
            roster::limits::DEFAULT_SNAPSHOT_WINDOW,
        )
        .expect("valid");
        let device = founder.device_spec("nas", Role::Admin, true, vec![]).expect("spec");
        let core = OperationCore::new(
            1_757_000_040_000,
            founder.signing_key().algorithm(),
            OperationBody::CreateNetwork { device, params },
            vec![],
            founder.signing_key().public_key().key_id(),
            roster::id::NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed");
        let bytes = sign_operation(&core, founder.signer()).expect("signs");
        let mut roster = Roster::new();
        assert!(roster.offer_bytes(&bytes).is_accepted());
        (roster, founder)
    }

    #[test]
    fn an_admin_attests_and_its_own_roster_accepts_it() {
        let (mut roster, founder) = founded();
        let bytes = sign_over_heads(&roster, &founder).expect("signs");
        assert!(roster.offer_attestation(&bytes).is_accepted(), "signed over its own heads");
    }

    #[test]
    fn a_member_attests_to_nothing() {
        let (roster, _founder) = founded();
        let stranger = NodeIdentity::generate().expect("generates");
        assert!(
            sign_over_heads(&roster, &stranger).is_err(),
            "a device the roster does not name as an admin produces nothing"
        );
    }

    #[test]
    fn the_sequence_advances_with_each_one() {
        let (mut roster, founder) = founded();
        let first = sign_over_heads(&roster, &founder).expect("signs");
        assert!(roster.offer_attestation(&first).is_accepted());
        let second = sign_over_heads(&roster, &founder).expect("signs");
        assert!(roster.offer_attestation(&second).is_accepted(), "the second advances");
    }

    #[test]
    fn one_is_due_before_any_has_been_made_and_not_straight_after() {
        let (mut roster, founder) = founded();
        assert!(due(&roster, &founder, 0), "nothing held, so one is due");

        let bytes = sign_over_heads(&roster, &founder).expect("signs");
        assert!(roster.offer_attestation(&bytes).is_accepted());
        let at = roster.attestation_received_at().expect("dated");

        assert!(!due(&roster, &founder, at), "not again at once");
        assert!(!due(&roster, &founder, at.saturating_add(PERIOD)), "nor at the period exactly");
        assert!(due(&roster, &founder, at.saturating_add(PERIOD).saturating_add(1)), "after it");
    }

    #[test]
    fn a_member_is_never_due() {
        let (roster, _founder) = founded();
        let stranger = NodeIdentity::generate().expect("generates");
        assert!(!due(&roster, &stranger, u64::MAX), "and so never reaches for a key");
    }

    /// A clock that moved backwards makes the pair of readings incomparable, so
    /// the safe answer is to sign again and date both by the same clock.
    #[test]
    fn a_receipt_in_the_future_makes_one_due() {
        let (mut roster, founder) = founded();
        let bytes = sign_over_heads(&roster, &founder).expect("signs");
        assert!(roster.restore_attestation(&bytes, 10_000).is_accepted());
        assert!(due(&roster, &founder, 5_000));
    }

    /// The period is a seventh of the window, not a quarter of it. At seven days
    /// a quarter is forty-two hours, which leaves a peer stale between sessions.
    #[test]
    fn the_period_is_well_inside_the_window() {
        assert_eq!(PERIOD, 43_200, "twelve hours");
        assert!(
            PERIOD.saturating_mul(6) < roster::limits::DEFAULT_SNAPSHOT_WINDOW,
            "six missed in a row must still be inside the window"
        );
    }
}

//! A light member: one current root, the deltas it remembers, no roster.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod support;

use roster::light::{LightView, ProofVerdict, RootOutcome, RootRefusal};
use roster::membership::MembershipProof;
use roster::sign::Signer as _;
use roster::snapshot::{Covering, Snapshot};
use roster::state::{RosterState, derive};
use roster::types::{OperationBody, Role};
use support::{History, device, device_id, signer};

/// The root of what `label` covers, signed by `seed`, following `previous`.
fn root_at(
    history: &History,
    label: &str,
    seed: u8,
    previous: Option<(&Snapshot, &RosterState)>,
) -> (Snapshot, RosterState) {
    let covered = history.covered_dag(&[label]);
    let state = derive(&covered).unwrap();
    let id = history.id(label);
    let depth = covered.depth(covered.position(&id).unwrap());
    let root = Snapshot::over(
        &state,
        Covering { heads: vec![id], depths: vec![depth] },
        signer(seed).key_id(),
        previous,
    )
    .unwrap();
    (root, state)
}

/// A network with two admins (1 and 9) and two members (2 and 3).
fn founded() -> History {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("admin9", 1, &["g"], OperationBody::AddDevice(device(9, "pc", Role::Admin, false)));
    history.op(
        "m2",
        1,
        &["admin9"],
        OperationBody::AddDevice(device(2, "sensor", Role::Member, false)),
    );
    history.op(
        "m3",
        1,
        &["m2"],
        OperationBody::AddDevice(device(3, "camera", Role::Member, false)),
    );
    history
}

/// Whether `view` accepts device `seed`'s proof made in `state`.
fn judged(view: &LightView, state: &RosterState, seed: u8) -> ProofVerdict {
    let device = device_id(seed);
    let leaf = state.leaf(&device).unwrap();
    let proof = MembershipProof::of(state, &device).unwrap();
    view.judge(&leaf, &proof, &state.root())
}

#[test]
fn a_following_root_is_adopted_and_a_member_proves_against_it() {
    let mut history = founded();
    let (first, first_state) = root_at(&history, "m3", 1, None);
    let mut view = LightView::starting_from(&first, 16);
    assert_eq!(judged(&view, &first_state, 2), ProofVerdict::Accepted);

    history.op(
        "rename3",
        1,
        &["m3"],
        OperationBody::Rename { device: device_id(3), name: "cam".into() },
    );
    let (second, second_state) = root_at(&history, "rename3", 1, Some((&first, &first_state)));
    assert_eq!(view.offer(&second), RootOutcome::Adopted);
    assert_eq!(view.current(), Some(second.root));
    assert_eq!(view.offer(&second), RootOutcome::AlreadyKnown);

    assert_eq!(judged(&view, &second_state, 3), ProofVerdict::Accepted);
    assert_eq!(
        judged(&view, &first_state, 2),
        ProofVerdict::Accepted,
        "an older proof still holds"
    );
    assert_eq!(
        judged(&view, &first_state, 3),
        ProofVerdict::Refused,
        "but not one of a leaf a later root changed"
    );
}

#[test]
fn a_revocation_cuts_an_older_proof() {
    let mut history = founded();
    let (first, first_state) = root_at(&history, "m3", 1, None);
    let mut view = LightView::starting_from(&first, 16);
    history.op(
        "revoke2",
        1,
        &["m3"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "stolen".into() },
    );
    let (second, _) = root_at(&history, "revoke2", 1, Some((&first, &first_state)));
    assert_eq!(second.delta, vec![device_id(2)]);
    assert_eq!(view.offer(&second), RootOutcome::Adopted);
    assert_eq!(judged(&view, &first_state, 2), ProofVerdict::Refused);
}

#[test]
fn siblings_converge_and_the_revocation_holds_on_either_branch() {
    let mut history = founded();
    let (base, base_state) = root_at(&history, "m3", 1, None);
    // Admin 1 revokes device 2 while admin 9, concurrently, renames device 3.
    history.op(
        "revoke2",
        1,
        &["m3"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "stolen".into() },
    );
    history.op(
        "rename3",
        9,
        &["m3"],
        OperationBody::Rename { device: device_id(3), name: "cam".into() },
    );
    let (revoking, _) = root_at(&history, "revoke2", 1, Some((&base, &base_state)));
    let (renaming, _) = root_at(&history, "rename3", 9, Some((&base, &base_state)));

    let mut one = LightView::starting_from(&base, 16);
    let mut other = LightView::starting_from(&base, 16);
    let _ = one.offer(&revoking);
    let _ = one.offer(&renaming);
    let _ = other.offer(&renaming);
    let _ = other.offer(&revoking);

    assert_eq!(one.current(), other.current(), "the heavier sibling wins the same way everywhere");
    for view in [&one, &other] {
        assert_eq!(
            judged(view, &base_state, 2),
            ProofVerdict::Refused,
            "the revoked device is refused whichever branch is current"
        );
    }
}

#[test]
fn a_root_signed_by_an_admin_a_sibling_demoted_is_refused() {
    let mut history = founded();
    let (base, base_state) = root_at(&history, "m3", 1, None);
    history.op("demote9", 1, &["m3"], OperationBody::Demote { device: device_id(9) });
    history.op(
        "rename3",
        9,
        &["m3"],
        OperationBody::Rename { device: device_id(3), name: "cam".into() },
    );
    let (demoting, _) = root_at(&history, "demote9", 1, Some((&base, &base_state)));
    let (by_nine, _) = root_at(&history, "rename3", 9, Some((&base, &base_state)));

    let mut view = LightView::starting_from(&base, 16);
    assert_eq!(view.offer(&demoting), RootOutcome::Adopted);
    assert_eq!(view.offer(&by_nine), RootOutcome::Refused(RootRefusal::SignerInvalidated));
}

#[test]
fn a_root_signed_by_a_member_is_refused() {
    let history = founded();
    let (base, base_state) = root_at(&history, "m3", 1, None);
    let mut view = LightView::starting_from(&base, 16);
    // A member signs a root following the base, with its own leaf as proof.
    let member = device_id(2);
    let forged = Snapshot::new(
        2,
        vec![base.root],
        [0x42; 32],
        Covering { heads: base.heads.clone(), depths: base.depths.clone() },
        vec![],
        base_state.leaf(&member).unwrap(),
        MembershipProof::of(&base_state, &member).unwrap(),
        signer(2).key_id(),
        base.network,
    )
    .unwrap();
    assert_eq!(view.offer(&forged), RootOutcome::Refused(RootRefusal::SignerNotProved));
}

#[test]
fn a_proof_older_than_memory_must_be_renewed() {
    let mut history = founded();
    let (first, first_state) = root_at(&history, "m3", 1, None);
    let mut view = LightView::starting_from(&first, 2);
    let mut previous = (first.clone(), first_state.clone());
    let mut parent = "m3".to_owned();
    for step in 0..3 {
        let label = format!("r{step}");
        history.op(
            &label,
            1,
            &[parent.as_str()],
            OperationBody::Rename { device: device_id(3), name: format!("n{step}") },
        );
        let next = root_at(&history, &label, 1, Some((&previous.0, &previous.1)));
        assert_eq!(view.offer(&next.0), RootOutcome::Adopted);
        previous = next;
        parent = label;
    }
    assert_eq!(view.remembered(), 2, "memory is bounded");
    assert_eq!(judged(&view, &first_state, 2), ProofVerdict::Renew);
    assert_eq!(judged(&view, &previous.1, 2), ProofVerdict::Accepted);
}

#[test]
fn a_root_following_one_not_remembered_needs_the_chain() {
    let mut history = founded();
    let (first, first_state) = root_at(&history, "m3", 1, None);
    history.op("r0", 1, &["m3"], OperationBody::Rename { device: device_id(3), name: "a".into() });
    let (second, second_state) = root_at(&history, "r0", 1, Some((&first, &first_state)));
    history.op("r1", 1, &["r0"], OperationBody::Rename { device: device_id(3), name: "b".into() });
    let (third, _) = root_at(&history, "r1", 1, Some((&second, &second_state)));

    let mut view = LightView::starting_from(&first, 16);
    assert_eq!(view.offer(&third), RootOutcome::NeedsChain);
    assert_eq!(view.offer(&second), RootOutcome::Adopted);
    assert_eq!(view.offer(&third), RootOutcome::Adopted);
}

//! What holds together, and what a person is told — each refusal and each kind.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use daemon::control::{Command, SignaturesWanted, SigningKind, Target, ToSign};
use identity::NodeIdentity;
use roster::id::{DeviceId, NetworkId, OperationId};
use roster::snapshot::Snapshot;
use roster::types::{NetworkParams, OperationBody, OperationCore, Role};

use super::{Read, describe, holds_together, listed, matches_what_was_asked, read, summary};

/// A network's admin, and the network its operations name.
struct Admin {
    identity: NodeIdentity,
    network: NetworkId,
}

impl Admin {
    fn new() -> Self {
        Self {
            identity: NodeIdentity::generate().unwrap(),
            network: NetworkId::from_bytes([0x42; 32]),
        }
    }

    fn core(&self, body: OperationBody, parents: Vec<OperationId>) -> OperationCore {
        OperationCore::new(
            1_735_689_600_000,
            self.identity.signing_key().algorithm(),
            body,
            parents,
            self.identity.signing_key().key_id(),
            self.network,
        )
        .unwrap()
    }

    fn snapshot_over(&self, heads: Vec<OperationId>) -> Snapshot {
        let depths = vec![1; heads.len()];
        Snapshot::new(
            7,
            vec![0xa0],
            heads,
            depths,
            self.identity.signing_key().key_id(),
            self.network,
        )
        .unwrap()
    }
}

fn params() -> NetworkParams {
    NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "home.internal", 2_592_000).unwrap()
}

fn operation(core: &OperationCore) -> ToSign {
    ToSign { kind: SigningKind::Operation, message: vec![1], payload: core.encode() }
}

fn snapshot(body: &Snapshot) -> ToSign {
    ToSign { kind: SigningKind::Snapshot, message: vec![2], payload: body.encode() }
}

fn proof() -> ToSign {
    ToSign { kind: SigningKind::Possession, message: vec![7; 32], payload: Vec::new() }
}

fn batch(network: &str, items: Vec<ToSign>) -> SignaturesWanted {
    SignaturesWanted {
        id: "b1".to_owned(),
        key: "k".to_owned(),
        network: network.to_owned(),
        items,
    }
}

fn revocation(admin: &Admin, parents: Vec<OperationId>) -> OperationCore {
    admin.core(
        OperationBody::RevokeDevice {
            device: DeviceId::from_bytes([0x11; 32]),
            reason: "sold".to_owned(),
        },
        parents,
    )
}

fn admission(admin: &Admin, parents: Vec<OperationId>) -> OperationCore {
    let joiner = NodeIdentity::generate().unwrap();
    admin.core(
        OperationBody::AddDevice(
            joiner.device_spec("laptop", Role::Member, false, Vec::new()).unwrap(),
        ),
        parents,
    )
}

fn revoking(network: Option<&str>) -> Command {
    Command::Revoke {
        network: network.map(str::to_owned),
        target: Target::Name("laptop".to_owned()),
        reason: "sold".to_owned(),
    }
}

// ---- what holds together ---------------------------------------------------

/// The ordinary act: one operation, and the snapshot over it.
#[test]
fn an_act_and_its_snapshot_hold_together() {
    let admin = Admin::new();
    let revoke = revocation(&admin, Vec::new());
    let over = admin.snapshot_over(vec![revoke.id()]);
    let read =
        holds_together(&revoking(None), &batch("casa", vec![operation(&revoke), snapshot(&over)]))
            .expect("one act");
    assert_eq!(2, read.len());
}

/// A replacement: a revocation, the admission built on it, and the snapshot
/// over both — for an admission confirmation, and nothing else.
#[test]
fn a_replacement_holds_together_only_as_an_admission() {
    let admin = Admin::new();
    let revoke = revocation(&admin, Vec::new());
    let admit = admission(&admin, vec![revoke.id()]);
    let over = admin.snapshot_over(vec![admit.id()]);
    let items = || vec![operation(&revoke), operation(&admit), snapshot(&over)];

    assert!(holds_together(&Command::Replace, &batch("casa", items())).is_ok());
    assert!(holds_together(&Command::Confirm, &batch("casa", items())).is_ok());
    let refused = holds_together(&revoking(None), &batch("casa", items())).unwrap_err();
    assert!(refused.contains("two acts"), "{refused}");
}

#[test]
fn nothing_or_too_much_is_refused() {
    let refused = holds_together(&Command::Confirm, &batch("casa", Vec::new())).unwrap_err();
    assert!(refused.contains("0 signatures"), "{refused}");

    let admin = Admin::new();
    let one = revocation(&admin, Vec::new());
    let five = (0..5).map(|_| operation(&one)).collect();
    let refused = holds_together(&Command::Confirm, &batch("casa", five)).unwrap_err();
    assert!(refused.contains("5 signatures"), "{refused}");
}

#[test]
fn an_item_that_is_not_what_it_claims_is_refused() {
    let unreadable =
        ToSign { kind: SigningKind::Operation, message: vec![1], payload: b"no".to_vec() };
    let refused = holds_together(&Command::Confirm, &batch("casa", vec![unreadable])).unwrap_err();
    assert!(refused.contains("could not read"), "{refused}");

    // A snapshot sent as an operation is read as neither.
    let admin = Admin::new();
    let body = admin.snapshot_over(vec![OperationId::from_bytes([3; 32])]);
    let mislabelled =
        ToSign { kind: SigningKind::Operation, message: vec![1], payload: body.encode() };
    assert!(holds_together(&Command::Confirm, &batch("casa", vec![mislabelled])).is_err());

    // And a proof that carries something is not a proof.
    let carrying = ToSign { kind: SigningKind::Possession, message: vec![7; 32], payload: vec![1] };
    assert!(holds_together(&Command::Waiting, &batch("casa", vec![carrying])).is_err());
}

#[test]
fn a_proof_of_possession_comes_alone() {
    assert!(holds_together(&Command::Waiting, &batch("casa", vec![proof()])).is_ok());

    let admin = Admin::new();
    let revoke = revocation(&admin, Vec::new());
    let refused =
        holds_together(&Command::Waiting, &batch("casa", vec![proof(), operation(&revoke)]))
            .unwrap_err();
    assert!(refused.contains("proof of possession"), "{refused}");
}

#[test]
fn two_networks_are_refused() {
    let admin = Admin::new();
    let revoke = revocation(&admin, Vec::new());
    let mut elsewhere = admin.snapshot_over(vec![revoke.id()]);
    elsewhere.network = NetworkId::from_bytes([0x99; 32]);
    let refused = holds_together(
        &revoking(None),
        &batch("casa", vec![operation(&revoke), snapshot(&elsewhere)]),
    )
    .unwrap_err();
    assert!(refused.contains("more than one network"), "{refused}");
}

#[test]
fn acts_that_do_not_follow_one_another_are_refused() {
    let admin = Admin::new();
    let revoke = revocation(&admin, Vec::new());
    let beside = admission(&admin, Vec::new());
    let refused = holds_together(
        &Command::Replace,
        &batch("casa", vec![operation(&revoke), operation(&beside)]),
    )
    .unwrap_err();
    assert!(refused.contains("do not follow"), "{refused}");
}

#[test]
fn an_act_other_than_the_one_asked_for_is_refused() {
    let admin = Admin::new();
    let promotion = admin.core(
        OperationBody::Promote { device: DeviceId::from_bytes([0x11; 32]), founder: false },
        Vec::new(),
    );
    let refused =
        holds_together(&revoking(None), &batch("casa", vec![operation(&promotion)])).unwrap_err();
    assert!(refused.contains("not the act that was asked for"), "{refused}");
}

#[test]
fn a_snapshot_must_come_last_once_with_an_act_it_covers() {
    let admin = Admin::new();
    let revoke = revocation(&admin, Vec::new());
    let over = admin.snapshot_over(vec![revoke.id()]);
    let elsewhere = admin.snapshot_over(vec![OperationId::from_bytes([5; 32])]);

    let first =
        holds_together(&revoking(None), &batch("casa", vec![snapshot(&over), operation(&revoke)]));
    assert!(first.unwrap_err().contains("last"));
    let twice = holds_together(
        &revoking(None),
        &batch("casa", vec![operation(&revoke), snapshot(&over), snapshot(&over)]),
    );
    assert!(twice.unwrap_err().contains("more than one snapshot"));
    let alone = holds_together(&Command::Confirm, &batch("casa", vec![snapshot(&over)]));
    assert!(alone.unwrap_err().contains("on its own"));
    let uncovered = holds_together(
        &revoking(None),
        &batch("casa", vec![operation(&revoke), snapshot(&elsewhere)]),
    );
    assert!(uncovered.unwrap_err().contains("does not cover"));
}

/// **The label is the daemon's one word, and it must agree with the one the
/// person typed.**
#[test]
fn a_network_named_differently_from_the_one_typed_is_refused() {
    let admin = Admin::new();
    let revoke = revocation(&admin, Vec::new());
    assert!(
        holds_together(&revoking(Some("casa")), &batch("casa", vec![operation(&revoke)])).is_ok()
    );
    let refused =
        holds_together(&revoking(Some("ufficio")), &batch("casa", vec![operation(&revoke)]))
            .unwrap_err();
    assert!(refused.contains("you named `ufficio`"), "{refused}");
}

/// **A settings change must carry the value typed.** A daemon that kept the act
/// and changed the address would otherwise have it signed.
#[test]
fn a_settings_change_must_carry_what_was_typed() {
    let admin = Admin::new();
    let meeting = params().meeting_at("https://meet.example:8444").unwrap();
    let change = admin.core(OperationBody::SetNetwork(meeting), Vec::new());
    let asked = |address: &str| Command::ChangeRendezvous {
        network: None,
        rendezvous: Some(address.to_owned()),
    };
    assert!(matches_what_was_asked(&asked("https://meet.example:8444"), &change));
    assert!(!matches_what_was_asked(&asked("https://other.example:8444"), &change));
    let removing = Command::ChangeRendezvous { network: None, rendezvous: None };
    assert!(!matches_what_was_asked(&removing, &change), "a removal is not a change of address");

    let moved = params().switching_to("https://relay.example", None).unwrap();
    let moving = admin.core(OperationBody::SetNetwork(moved), Vec::new());
    let relay = |address: &str| Command::ChangeRelay {
        network: None,
        relay: address.to_owned(),
        pin: false,
        immediately: true,
    };
    assert!(matches_what_was_asked(&relay("https://relay.example"), &moving));
    assert!(!matches_what_was_asked(&relay("https://elsewhere.example"), &moving));
}

/// The reason a revocation gives is the one typed.
#[test]
fn a_revocation_must_carry_the_reason_typed() {
    let admin = Admin::new();
    let revoke = revocation(&admin, Vec::new());
    assert!(matches_what_was_asked(&revoking(None), &revoke));
    let other = Command::Revoke {
        network: None,
        target: Target::Name("laptop".to_owned()),
        reason: "lost".to_owned(),
    };
    assert!(!matches_what_was_asked(&other, &revoke));
}

// ---- what a person is told -------------------------------------------------

fn said(item: &Read, asked: &Command) -> String {
    let described = describe(item, "casa", asked);
    format!("{} / {}", described.act, described.consequence)
}

/// One per kind: the act, read off the bytes, and what follows from it.
#[test]
fn every_kind_says_what_it_does_and_what_follows() {
    let admin = Admin::new();

    let founder = admin.identity.device_spec("desktop", Role::Admin, true, Vec::new()).unwrap();
    let founding =
        admin.core(OperationBody::CreateNetwork { device: founder, params: params() }, Vec::new());
    let text = said(&Read::Operation(Box::new(founding)), &Command::Confirm);
    assert!(text.contains("found casa") && text.contains("`desktop`"), "{text}");
    assert!(text.contains("every admin act"), "{text}");

    let text = said(&Read::Operation(Box::new(revocation(&admin, Vec::new()))), &revoking(None));
    assert!(text.contains("revoke `laptop`") && text.contains("sold"), "{text}");
    assert!(text.contains("permanent"), "{text}");

    let text = said(&Read::Operation(Box::new(admission(&admin, Vec::new()))), &Command::Confirm);
    assert!(text.contains("admit `laptop`") && text.contains("a member"), "{text}");
    assert!(text.contains("reach the devices in casa"), "{text}");

    let device = DeviceId::from_bytes([0x11; 32]);
    let promote = admin.core(OperationBody::Promote { device, founder: false }, Vec::new());
    let text = said(&Read::Operation(Box::new(promote)), &Command::Confirm);
    assert!(text.contains("an admin") && text.contains("admit and revoke"), "{text}");

    let demote = admin.core(OperationBody::Demote { device }, Vec::new());
    let text = said(&Read::Operation(Box::new(demote)), &Command::Confirm);
    assert!(text.contains("a member") && text.contains("no longer"), "{text}");

    let rename = admin.core(OperationBody::Rename { device, name: "desk".to_owned() }, Vec::new());
    let text = said(&Read::Operation(Box::new(rename)), &Command::Confirm);
    assert!(text.contains("rename") && text.contains("`desk`"), "{text}");

    let body = admin.snapshot_over(vec![OperationId::from_bytes([3; 32])]);
    let text = said(&Read::Snapshot(body), &Command::Confirm);
    assert!(text.contains("current membership") && text.contains("snapshot 7"), "{text}");
    assert!(text.contains("routine") && text.contains("nobody's access changes"), "{text}");
    assert!(!text.contains("head"), "no jargon: {text}");

    let text = said(&Read::Possession, &Command::Waiting);
    assert!(text.contains("prove") && text.contains("no roster changes"), "{text}");
}

/// A settings change shows the new values: relay, the pinned certificate's
/// fingerprint, rendezvous, IPv4 range — and that everybody follows them.
#[test]
fn a_settings_change_shows_its_values() {
    let admin = Admin::new();
    let certificate = vec![0x30, 0x82, 0x01, 0x0a];
    let changed = params()
        .switching_to("https://relay.example", Some(certificate.clone()))
        .unwrap()
        .meeting_at("https://meet.example:8444")
        .unwrap();
    let change = admin.core(OperationBody::SetNetwork(changed), Vec::new());
    let text = said(&Read::Operation(Box::new(change)), &Command::Confirm);
    assert!(text.contains("relay.example"), "{text}");
    assert!(text.contains(&daemon::relay::fingerprint(&certificate)), "{text}");
    assert!(text.contains("meet.example"), "{text}");
    assert!(text.contains("IPv4 range"), "{text}");
    assert!(text.contains("every device in casa follows this"), "{text}");
}

/// **No name the daemon supplied is shown as the act's.** A revocation by id
/// carries no name in its bytes and the person typed none, so none is shown.
#[test]
fn no_daemon_supplied_name_is_shown_as_the_acts() {
    let admin = Admin::new();
    let by_id = Command::Revoke {
        network: None,
        target: Target::Id("1111-1111-1111-1111".to_owned()),
        reason: "sold".to_owned(),
    };
    let text = said(&Read::Operation(Box::new(revocation(&admin, Vec::new()))), &by_id);
    assert!(!text.contains('`'), "nothing named: {text}");
    let id = daemon::control::short_id(&DeviceId::from_bytes([0x11; 32]));
    assert!(text.contains(&id), "{text}");
}

/// The list names the network and numbers every act, with its consequence.
#[test]
fn the_list_names_the_network_and_every_act() {
    let admin = Admin::new();
    let revoke = revocation(&admin, Vec::new());
    let admit = admission(&admin, vec![revoke.id()]);
    let over = admin.snapshot_over(vec![admit.id()]);
    let read = holds_together(
        &Command::Replace,
        &batch("ufficio", vec![operation(&revoke), operation(&admit), snapshot(&over)]),
    )
    .unwrap();

    let shown = listed(&read, "ufficio", &Command::Replace);
    assert!(shown.starts_with("ufficio: 3 acts to sign with this network's admin key"), "{shown}");
    assert!(shown.contains("  1. revoke"), "{shown}");
    assert!(shown.contains("  2. admit"), "{shown}");
    assert!(shown.contains("  3. record"), "{shown}");
    assert!(shown.contains("permanent"), "{shown}");

    let line = summary(&read, "ufficio", &Command::Replace);
    assert!(line.starts_with("peerfectly · ufficio: revoke"), "{line}");
    assert!(!line.contains('\n'), "one line: {line}");
}

/// A proof of possession is said to be one, made with this device's own key.
#[test]
fn a_proof_is_listed_as_a_proof() {
    let read = vec![read(&proof()).unwrap()];
    let shown = listed(&read, "casa", &Command::Waiting);
    assert!(shown.contains("a proof to sign with this device's own signing key"), "{shown}");
}

/// **A network being joined has no name here yet**, and is said to be the one
/// being joined rather than shown as a blank or a placeholder.
#[test]
fn a_network_being_joined_is_called_that() {
    let read = vec![read(&proof()).unwrap()];
    let shown = listed(&read, "", &Command::Waiting);
    assert!(shown.starts_with("the network being joined: a proof"), "{shown}");
    assert!(holds_together(&Command::Waiting, &batch("", vec![proof()])).is_ok());
}

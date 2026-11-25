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
            vec![[0xa0; 32]],
            [0xa0; 32],
            roster::snapshot::Covering { heads, depths },
            Vec::new(),
            roster::snapshot::RootSigner::Device {
                leaf: roster::leaf::DeviceLeaf {
                    record: self
                        .identity
                        .device_spec("pc", roster::types::Role::Admin, Vec::new())
                        .unwrap()
                        .into_record(roster::id::OperationId::from_bytes([1; 32]))
                        .unwrap(),
                    settings: roster::leaf::DeviceSettings::default(),
                },
                proof: roster::membership::MembershipProof {
                    devices: roster::merkle::Proof { siblings: Vec::new() },
                    parameters: [0; 32],
                },
            },
            self.identity.signing_key().key_id(),
            self.network,
        )
        .unwrap()
    }
}

fn params() -> NetworkParams {
    NetworkParams::new(
        roster::types::FounderKeys::held_by_nobody(),
        vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
        "home.internal",
        2_592_000,
    )
    .unwrap()
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
        keys: None,
        founder: None,
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
        OperationBody::AddDevice(joiner.device_spec("laptop", Role::Member, Vec::new()).unwrap()),
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

/// An approval of the request for `laptop`, replacing the device holding the
/// name or not.
fn approving(replace: bool) -> Command {
    Command::Approve { network: None, name: "laptop".to_owned(), replace }
}

/// A replacement: a revocation, the admission built on it, and the snapshot
/// over both — for an approval that replaces, and nothing else.
#[test]
fn a_replacement_holds_together_only_as_an_admission() {
    let admin = Admin::new();
    let revoke = revocation(&admin, Vec::new());
    let admit = admission(&admin, vec![revoke.id()]);
    let over = admin.snapshot_over(vec![admit.id()]);
    let items = || vec![operation(&revoke), operation(&admit), snapshot(&over)];

    assert!(holds_together(&approving(true), &batch("casa", items())).is_ok());
    let refused = holds_together(&approving(false), &batch("casa", items())).unwrap_err();
    assert!(
        refused.contains("two acts"),
        "an approval that does not replace revokes nothing: {refused}"
    );
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
        &approving(true),
        &batch("casa", vec![operation(&revoke), operation(&beside)]),
    )
    .unwrap_err();
    assert!(refused.contains("do not follow"), "{refused}");
}

#[test]
fn an_act_other_than_the_one_asked_for_is_refused() {
    let admin = Admin::new();
    let promotion =
        admin.core(OperationBody::Promote { device: DeviceId::from_bytes([0x11; 32]) }, Vec::new());
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

    // A relay as it is written: its key, at its address.
    let key: String = NodeIdentity::generate()
        .unwrap()
        .transport_key()
        .public_key()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let at = |host: &str| format!("{key}@{host}");
    let moved = params().switching_to(at("relay.example:7400")).unwrap();
    let moving = admin.core(OperationBody::SetNetwork(moved), Vec::new());
    let relay = |address: &str| Command::ChangeRelay {
        network: None,
        relay: address.to_owned(),
        immediately: true,
    };
    assert!(matches_what_was_asked(&relay(&at("RELAY.example:7400")), &moving));
    assert!(!matches_what_was_asked(&relay(&at("elsewhere.example:7400")), &moving));

    // Given as its host, the relay signed must be on that host.
    assert!(matches_what_was_asked(&relay("relay.example"), &moving));
    assert!(!matches_what_was_asked(&relay("elsewhere.example"), &moving));
}

/// An anchor list signed holds one anchor for each name typed, case aside; and
/// is described with the anchors it sets.
#[test]
fn an_anchor_list_must_be_as_long_as_the_names_typed() {
    let admin = Admin::new();
    let one = DeviceId::from_bytes([1; 32]);
    let two = DeviceId::from_bytes([2; 32]);
    let setting = |anchors: Vec<DeviceId>| {
        admin.core(OperationBody::SetNetwork(params().with_anchors(anchors).unwrap()), Vec::new())
    };
    let named = |names: &[&str]| Command::SetAnchors {
        network: None,
        anchors: names.iter().map(|name| Target::Name((*name).to_owned())).collect(),
    };
    assert!(matches_what_was_asked(&named(&["nas", "server"]), &setting(vec![one, two])));
    assert!(matches_what_was_asked(&named(&["nas", "NAS"]), &setting(vec![one])), "case aside");
    assert!(!matches_what_was_asked(&named(&["nas"]), &setting(vec![one, two])), "one more");
    assert!(!matches_what_was_asked(&named(&["nas", "server"]), &setting(vec![one])));
    assert!(matches_what_was_asked(&named(&[]), &setting(Vec::new())), "a clearing");

    let described =
        describe(&Read::Operation(Box::new(setting(vec![one]))), "casa", &named(&["nas"])).act;
    assert!(described.contains(&daemon::control::short_id(&one)), "{described}");
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

/// A founding typed with `--name Laptop` is signed as `laptop`, which is the
/// founding asked for. Before the CLI compared names as the daemon keeps them,
/// it refused its own founding.
#[test]
fn a_founding_typed_in_upper_case_is_the_one_asked_for() {
    let admin = Admin::new();
    let founder = admin.identity.device_spec("laptop", Role::Admin, Vec::new()).unwrap();
    let founding =
        admin.core(OperationBody::CreateNetwork { device: founder, params: params() }, Vec::new());
    let asked = |name: &str| Command::Found {
        founder: daemon::control::FounderPublic::of(&roster::types::FounderKeys::held_by_nobody()),
        label: "casa".to_owned(),
        name: name.to_owned(),
        suffix: "home.internal".to_owned(),
        relay: None,
        ipv4_range: None,
        devices: None,
        window_days: None,
    };
    assert!(matches_what_was_asked(&asked("Laptop"), &founding));
    assert!(matches_what_was_asked(&asked("laptop"), &founding));
    assert!(!matches_what_was_asked(&asked("desktop"), &founding));
}

/// A name is compared as the daemon keeps it: in lower case, so `Laptop` typed
/// is `laptop` signed, and any other name is refused.
#[test]
fn a_rename_must_carry_the_name_typed_in_lower_case() {
    let admin = Admin::new();
    let rename = admin.core(
        OperationBody::Rename {
            device: DeviceId::from_bytes([0x11; 32]),
            name: "studio".to_owned(),
        },
        Vec::new(),
    );
    let asked = |name: &str| Command::Rename {
        network: None,
        target: Target::Name("laptop".to_owned()),
        name: name.to_owned(),
    };
    assert!(matches_what_was_asked(&asked("studio"), &rename));
    assert!(matches_what_was_asked(&asked("Studio"), &rename));
    assert!(!matches_what_was_asked(&asked("office"), &rename));
    assert!(!matches_what_was_asked(&asked("stu dio"), &rename), "no name matches nothing");
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

    let founder = admin.identity.device_spec("desktop", Role::Admin, Vec::new()).unwrap();
    let founding =
        admin.core(OperationBody::CreateNetwork { device: founder, params: params() }, Vec::new());
    let text = said(&Read::Operation(Box::new(founding)), &Command::Confirm);
    assert!(text.contains("found casa") && text.contains("`desktop`"), "{text}");
    assert!(text.contains("every admin act"), "{text}");

    let text = said(&Read::Operation(Box::new(revocation(&admin, Vec::new()))), &revoking(None));
    assert!(text.contains("revoke `laptop`") && text.contains("sold"), "{text}");
    assert!(text.contains("invited again"), "{text}");

    let text = said(&Read::Operation(Box::new(admission(&admin, Vec::new()))), &Command::Confirm);
    assert!(text.contains("admit `laptop`") && text.contains("a member"), "{text}");
    assert!(text.contains("reach the devices in casa"), "{text}");

    let device = DeviceId::from_bytes([0x11; 32]);
    let promote = admin.core(OperationBody::Promote { device }, Vec::new());
    let text = said(&Read::Operation(Box::new(promote)), &Command::Confirm);
    assert!(text.contains("an admin") && text.contains("admit and revoke"), "{text}");

    let demote = admin.core(OperationBody::Demote { device }, Vec::new());
    let text = said(&Read::Operation(Box::new(demote.clone())), &Command::Confirm);
    assert!(text.contains("a member") && text.contains("no longer"), "{text}");
    assert!(text.contains("once the demotion is settled"), "{text}");
    let asked = Command::Demote { network: None, target: Target::Name("desk".to_owned()) };
    let text = said(&Read::Operation(Box::new(demote)), &asked);
    assert!(text.contains("make `desk` ("), "the name the person typed: {text}");

    let rename = admin.core(OperationBody::Rename { device, name: "desk".to_owned() }, Vec::new());
    let text = said(&Read::Operation(Box::new(rename)), &Command::Confirm);
    assert!(text.contains("rename") && text.contains("`desk`"), "{text}");
    let asked = Command::Rename {
        network: None,
        target: Target::Name("laptop".to_owned()),
        name: "desk".to_owned(),
    };
    let text = said(
        &Read::Operation(Box::new(
            admin.core(OperationBody::Rename { device, name: "desk".to_owned() }, Vec::new()),
        )),
        &asked,
    );
    assert!(text.contains("rename `laptop` (") && text.contains("to `desk`"), "{text}");

    let body = admin.snapshot_over(vec![OperationId::from_bytes([3; 32])]);
    let text = said(&Read::Snapshot(Box::new(body)), &Command::Confirm);
    assert!(text.contains("current membership") && text.contains("snapshot 7"), "{text}");
    assert!(text.contains("routine") && text.contains("nobody's access changes"), "{text}");
    assert!(!text.contains("head"), "no jargon: {text}");

    let text = said(&Read::Possession, &Command::Waiting);
    assert!(text.contains("prove") && text.contains("no roster changes"), "{text}");
}

/// A settings change shows the new values: relay, IPv4 block — and that
/// everybody follows them.
#[test]
fn a_settings_change_shows_its_values() {
    let admin = Admin::new();
    let changed = params().switching_to("https://relay.example").unwrap();
    let change = admin.core(OperationBody::SetNetwork(changed), Vec::new());
    let text = said(&Read::Operation(Box::new(change)), &Command::Confirm);
    assert!(text.contains("relay.example"), "{text}");
    assert!(text.contains("IPv4 block"), "{text}");
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
        &approving(true),
        &batch("ufficio", vec![operation(&revoke), operation(&admit), snapshot(&over)]),
    )
    .unwrap();

    let shown = listed(&read, "ufficio", &approving(true));
    assert!(shown.starts_with("ufficio: 3 acts to sign with this network's admin key"), "{shown}");
    assert!(shown.contains("  1. revoke"), "{shown}");
    assert!(shown.contains("  2. admit"), "{shown}");
    assert!(shown.contains("  3. record"), "{shown}");
    assert!(shown.contains("invited again"), "{shown}");

    let line = summary(&read, "ufficio", &approving(true));
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

// ---- the founder's acts ----------------------------------------------------

/// The founder's words of these tests, and an operation authored by them.
struct Founder {
    key: identity::founder::FounderKey,
    network: NetworkId,
}

impl Founder {
    fn new() -> Self {
        Self {
            key: identity::founder::FounderKey::generate().unwrap(),
            network: NetworkId::from_bytes([0x42; 32]),
        }
    }

    fn core(&self, body: OperationBody, parents: Vec<OperationId>) -> OperationCore {
        OperationCore::new(
            1_735_689_600_000,
            roster::types::Algorithm::Ed25519,
            body,
            parents,
            self.key.keys().signing_id(),
            self.network,
        )
        .unwrap()
    }

    fn wanted(&self, items: Vec<ToSign>) -> SignaturesWanted {
        SignaturesWanted {
            founder: Some(daemon::control::FounderPublic::of(&self.key.keys())),
            ..batch("home", items)
        }
    }
}

fn recovering(named: &[&str]) -> Command {
    Command::Recover {
        network: Some("home".to_owned()),
        revoke: named.iter().map(|name| Target::Name((*name).to_owned())).collect(),
        another_name: false,
    }
}

/// A recovery's chain on a member: the admin named, the new identity admitted
/// as an admin, where the batch has room its address, and the old identity
/// revoked last.
fn recovery_chain(
    founder: &Founder,
    address: Option<roster::leaf::SettingsChange>,
) -> Vec<OperationCore> {
    let revoke_admin = founder.core(
        OperationBody::RevokeDevice {
            device: DeviceId::from_bytes([0x11; 32]),
            reason: "x".to_owned(),
        },
        Vec::new(),
    );
    let new = NodeIdentity::generate().unwrap();
    let spec = new.device_spec("phone", Role::Admin, Vec::new()).unwrap();
    let device = spec.device_id().unwrap();
    let admit = founder.core(OperationBody::AddDevice(spec), vec![revoke_admin.id()]);
    let mut chain = vec![revoke_admin, admit];
    if let Some(change) = address {
        let parent = chain.last().unwrap().id();
        chain.push(founder.core(OperationBody::SetDevice { device, change }, vec![parent]));
    }
    let parent = chain.last().unwrap().id();
    chain.push(founder.core(
        OperationBody::RevokeDevice {
            device: DeviceId::from_bytes([0x22; 32]),
            reason: "y".to_owned(),
        },
        vec![parent],
    ));
    chain
}

fn an_address() -> roster::leaf::SettingsChange {
    roster::leaf::SettingsChange { ipv4: Some(Some([0, 0, 0, 3])), ..Default::default() }
}

#[test]
fn a_recovery_holds_together_with_or_without_the_new_identitys_address() {
    let founder = Founder::new();
    for address in [None, Some(an_address())] {
        let chain = recovery_chain(&founder, address);
        let wanted = founder.wanted(chain.iter().map(operation).collect());
        assert!(holds_together(&recovering(&["nas"]), &wanted).is_ok());
    }
}

/// The address the old identity held comes after its revocation, and only
/// there: given to the new identity, nothing else changed.
#[test]
fn a_recovery_keeping_the_old_address_gives_it_after_the_revocation() {
    let founder = Founder::new();
    let mut chain = recovery_chain(&founder, None);
    let device = match &chain.get(1).unwrap().body {
        OperationBody::AddDevice(spec) => spec.device_id().unwrap(),
        other => panic!("the admission, not {other:?}"),
    };
    let parent = chain.last().unwrap().id();
    chain.push(
        founder.core(OperationBody::SetDevice { device, change: an_address() }, vec![parent]),
    );
    let wanted = founder.wanted(chain.iter().map(operation).collect());
    assert!(holds_together(&recovering(&["nas"]), &wanted).is_ok());

    // Of another device, or more than the address, it is refused.
    let mut other = chain.clone();
    other.pop();
    let parent = other.last().unwrap().id();
    other.push(founder.core(
        OperationBody::SetDevice { device: DeviceId::from_bytes([0x33; 32]), change: an_address() },
        vec![parent],
    ));
    let wanted = founder.wanted(other.iter().map(operation).collect());
    assert!(holds_together(&recovering(&["nas"]), &wanted).is_err());
}

#[test]
fn a_recovery_that_changes_more_than_the_address_is_refused() {
    let founder = Founder::new();
    let more =
        roster::leaf::SettingsChange { mode: Some(roster::leaf::Mode::Light), ..an_address() };
    let removed = roster::leaf::SettingsChange { ipv4: Some(None), ..Default::default() };
    for change in [more, removed] {
        let chain = recovery_chain(&founder, Some(change));
        let wanted = founder.wanted(chain.iter().map(operation).collect());
        assert!(holds_together(&recovering(&["nas"]), &wanted).is_err());
    }
}

#[test]
fn a_recovery_revoking_other_than_the_admins_named_is_refused() {
    let founder = Founder::new();
    let chain = recovery_chain(&founder, None);
    let wanted = founder.wanted(chain.iter().map(operation).collect());
    assert!(holds_together(&recovering(&["nas"]), &wanted).is_ok());
    for named in [&[][..], &["nas", "desk"][..]] {
        assert!(holds_together(&recovering(named), &wanted).is_err(), "{named:?}");
    }
}

/// The revocation that ends the chain is the old identity's: one of the
/// device just admitted would leave the network without the admin it was for.
#[test]
fn a_recovery_revoking_the_device_it_admits_is_refused() {
    let founder = Founder::new();
    let new = NodeIdentity::generate().unwrap();
    let spec = new.device_spec("phone", Role::Admin, Vec::new()).unwrap();
    let device = spec.device_id().unwrap();
    let admit = founder.core(OperationBody::AddDevice(spec), Vec::new());
    let revoke = founder
        .core(OperationBody::RevokeDevice { device, reason: "y".to_owned() }, vec![admit.id()]);
    let wanted = founder.wanted(vec![operation(&admit), operation(&revoke)]);
    assert!(holds_together(&recovering(&[]), &wanted).is_err());
}

#[test]
fn a_recovery_admitting_a_member_is_refused() {
    let founder = Founder::new();
    let revoke = founder.core(
        OperationBody::RevokeDevice {
            device: DeviceId::from_bytes([0x11; 32]),
            reason: "x".to_owned(),
        },
        Vec::new(),
    );
    let joiner = NodeIdentity::generate().unwrap();
    let admit = founder.core(
        OperationBody::AddDevice(joiner.device_spec("phone", Role::Member, Vec::new()).unwrap()),
        vec![revoke.id()],
    );
    let wanted = founder.wanted(vec![operation(&revoke), operation(&admit)]);
    assert!(holds_together(&recovering(&["nas"]), &wanted).is_err());
}

#[test]
fn an_act_the_founder_signs_must_be_authored_by_the_founder() {
    let founder = Founder::new();
    let admin = Admin::new();
    let asked = Command::AsFounder(Box::new(revoking(Some("home"))));
    let by_the_founder = founder.core(
        OperationBody::RevokeDevice {
            device: DeviceId::from_bytes([0x11; 32]),
            reason: "sold".to_owned(),
        },
        Vec::new(),
    );
    assert!(holds_together(&asked, &founder.wanted(vec![operation(&by_the_founder)])).is_ok());
    let by_the_admin = revocation(&admin, Vec::new());
    assert!(holds_together(&asked, &founder.wanted(vec![operation(&by_the_admin)])).is_err());
    // And the founder is never asked for an act the person did not ask it to sign.
    assert!(
        holds_together(&revoking(Some("home")), &founder.wanted(vec![operation(&by_the_founder)]))
            .is_err()
    );
}

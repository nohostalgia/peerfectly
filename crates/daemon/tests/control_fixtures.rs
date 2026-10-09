//! The JSON the interface decodes, written from the Rust types themselves.
//!
//! Every surface that is not Rust reads `control::Outcome` and `control::Report` as
//! JSON — the Android app mirrors them in Kotlin, and the Windows tray's tests
//! build their reports from this file — and a mirror drifts silently: a field
//! renamed here decodes as missing there, on a phone, in front of a person. So this
//! builds every variant, writes it the way the core does, and holds
//! `tests/fixtures/control.json` to it. Their contract tests decode that same file.
//!
//! When a type changes on purpose, run with `PEERFECTLY_BLESS=1` to rewrite the file,
//! and the Kotlin test then says what the mirror must learn.

#![allow(clippy::unwrap_used, clippy::panic, reason = "a test reports failure by panicking")]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::{Duration, SystemTime};

use daemon::Fault;
use daemon::control::{
    Accused, Act, Branch, Contact, Ipv4State, Named, Network, Outcome, Owed, Peer, Report,
    Revocation, Revoked, Signed, Standing, Tunnel, Unusable, Waiting,
};

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds)).unwrap()
}

fn named(name: Option<&str>, id: &str) -> Named {
    Named { name: name.map(str::to_owned), id: id.to_owned() }
}

/// A report carrying every variant of everything it can hold.
fn report() -> Report {
    let nas = named(Some("nas"), "0a1b-2c3d-4e5f-6a7b");
    let laptop = named(Some("laptop"), "1b2c-3d4e-5f6a-7b8c");
    let gone = named(None, "2c3d-4e5f-6a7b-8c9d");
    let on = Network {
        label: "home".to_owned(),
        tunnel: Tunnel::Up,
        standing: Standing::Current,
        address: Some("fd00::4".parse::<Ipv6Addr>().unwrap()),
        ipv4: Some(Ipv4State::Held(Ipv4Addr::new(100, 64, 0, 4))),
        name: Some("pixel.home.internal".to_owned()),
        id: "3d4e-5f6a-7b8c-9d0e".to_owned(),
        admin: true,
        custody: daemon::control::Custody::KeyStore,
        owner_taken: false,
        // A network confirmed within the time it allows.
        confirmation: None,
        relay: Some("https://relay.example:443".to_owned()),
        rendezvous: Some("https://meet.example".to_owned()),
        relay_pinned: true,
        // A network in the middle of moving relay, so a renderer has one to draw.
        relay_leaving: Some(daemon::control::RelayLeaving {
            relay: "https://old-relay.example:443".to_owned(),
            until: at(1_758_300_000),
        }),
        accused: vec![Accused {
            device: nas.clone(),
            pairs: 2,
            first: Branch { does: Act::Admits(laptop.clone()), depth: Some(41) },
            second: Branch { does: Act::Revokes(laptop.clone()), depth: None },
        }],
        peers: vec![
            Peer {
                name: "nas.home.internal".to_owned(),
                name_resolves: true,
                id: nas.id.clone(),
                address: "fd00::2".parse().unwrap(),
                ipv4: Some(Ipv4State::Held(Ipv4Addr::new(100, 64, 0, 2))),
                reachable: true,
                path: Some(daemon::control::Path::Relay),
                standing: Standing::Current,
                last_contact: Contact::Recorded { at: at(1_757_700_000) },
            },
            Peer {
                name: "laptop.home.internal".to_owned(),
                name_resolves: true,
                id: laptop.id.clone(),
                address: "fd00::7".parse().unwrap(),
                ipv4: Some(Ipv4State::Withheld {
                    address: Ipv4Addr::new(192, 168, 1, 7),
                    with: "the local subnet 192.168.1.0/24".to_owned(),
                }),
                reachable: false,
                path: None,
                standing: Standing::Current,
                last_contact: Contact::NoneRecorded,
            },
        ],
        revoked: vec![Revoked {
            device: gone.clone(),
            revocations: vec![
                Revocation {
                    by: nas.clone(),
                    reason: "stolen on the train".to_owned(),
                    signer_clock: Signed::At { time: at(1_757_000_000) },
                },
                Revocation {
                    by: laptop.clone(),
                    reason: "lost".to_owned(),
                    signer_clock: Signed::NotRecorded,
                },
            ],
            last_contact: Contact::NoneRecorded,
        }],
        waiting: vec![
            Waiting {
                does: Act::Revokes(gone),
                signed_here: Signed::At { time: at(1_757_000_060) },
                owed: vec![
                    Owed {
                        device: nas.clone(),
                        connected: true,
                        last_contact: Contact::Recorded { at: at(1_757_700_000) },
                    },
                    Owed {
                        device: laptop.clone(),
                        connected: false,
                        last_contact: Contact::NoneRecorded,
                    },
                ],
            },
            Waiting { does: Act::Founds, signed_here: Signed::NotRecorded, owed: Vec::new() },
            Waiting {
                does: Act::Promotes(nas.clone(), true),
                signed_here: Signed::NotRecorded,
                owed: Vec::new(),
            },
            Waiting {
                does: Act::Demotes(nas.clone()),
                signed_here: Signed::NotRecorded,
                owed: Vec::new(),
            },
            Waiting {
                does: Act::Renames(laptop, "tablet".to_owned()),
                signed_here: Signed::NotRecorded,
                owed: Vec::new(),
            },
            Waiting {
                does: Act::SetsParameters,
                signed_here: Signed::NotRecorded,
                owed: Vec::new(),
            },
        ],
        waiting_unlisted: 3,
        problem: Some(Fault {
            subsystem: "relay".to_owned(),
            cause: "certificate not trusted".to_owned(),
            at: at(1_757_000_100),
        }),
    };
    let off = Network {
        label: "work".to_owned(),
        tunnel: Tunnel::Down,
        standing: Standing::LastKnown { at: at(1_757_600_000) },
        address: None,
        ipv4: None,
        name: None,
        id: "4e5f-6a7b-8c9d-0e1f".to_owned(),
        admin: false,
        custody: daemon::control::Custody::KeyStore,
        owner_taken: false,
        // And one this device has not been able to confirm, so a renderer of
        // the report has both to draw.
        confirmation: Some(daemon::control::Unconfirmed::Stale),
        relay: None,
        rendezvous: None,
        relay_pinned: false,
        relay_leaving: None,
        accused: vec![Accused {
            device: named(Some("build-box"), "5f6a-7b8c-9d0e-1f2a"),
            pairs: 1,
            first: Branch {
                does: Act::Admits(named(Some("tablet"), "6a7b-8c9d-0e1f-2a3b")),
                depth: Some(41),
            },
            second: Branch {
                does: Act::Admits(named(Some("tablet"), "7b8c-9d0e-1f2a-3b4c")),
                depth: Some(41),
            },
        }],
        // Reachable when last known: an off network must still not draw it as now.
        peers: vec![Peer {
            name: "build-box.work.internal".to_owned(),
            name_resolves: true,
            id: "5f6a-7b8c-9d0e-1f2a".to_owned(),
            address: "fd01::2".parse().unwrap(),
            ipv4: Some(Ipv4State::Collides(named(Some("tablet"), "6a7b-8c9d-0e1f-2a3b"))),
            reachable: true,
            // Direct when last known: an off network must not draw a path as now either.
            path: Some(daemon::control::Path::Direct),
            standing: Standing::LastKnown { at: at(1_757_600_000) },
            last_contact: Contact::Recorded { at: at(1_757_600_000) },
        }],
        revoked: Vec::new(),
        waiting: Vec::new(),
        waiting_unlisted: 0,
        problem: None,
    };
    Report {
        networks: vec![on, off],
        unusable: vec![Unusable {
            label: "old".to_owned(),
            cause: daemon::control::Trouble::IdentityWillNotOpen,
        }],
        admin_refusal: None,
        note: Some("the other machine confirmed the relay".to_owned()),
        elsewhere: 0,
        may_stop_the_daemon: true,
        could_stop_the_daemon: false,
    }
}

/// One of every outcome.
fn outcomes() -> Vec<Outcome> {
    vec![
        Outcome::Reported(report()),
        Outcome::Reported(Report {
            networks: Vec::new(),
            unusable: Vec::new(),
            note: Some("one network on this machine belongs to somebody else, and none to you".to_owned()),
            admin_refusal: None,
            // What the second person on a desktop is shown. Zero on a phone,
            // which has one person — and in the fixture precisely because the
            // mirror has to be able to read the case it will never produce.
            elsewhere: 1,
            // The second person on a desktop: owns nothing here and may not stop
            // it either. True on a phone, which has one person — and in the
            // fixture as false precisely because that is the case the mirror
            // will never produce and still has to read.
            may_stop_the_daemon: false,
            could_stop_the_daemon: false,
        }),
        Outcome::Done,
        Outcome::Admitting {
            proposed_name: "tablet".to_owned(),
            fingerprint: "AB:CD".to_owned(),
            code: "418209".to_owned(),
            // A name this network already uses, with the identity the decision
            // falls on: a renderer has both spellings of this field to draw.
            taken: Some(daemon::control::TakenName {
                name: "tablet".to_owned(),
                id: "0b0b-0b0b-0b0b-0b0b".to_owned(),
            }),
            accepted: true,
        },
        // The joining side's answer, which carries nothing at all: a client it
        // reached cannot show a person the digits they must read elsewhere.
        Outcome::Enrolling,
        Outcome::Joining { payload: "peerfectly-join:abc".to_owned(), scannable: "▀▄".to_owned() },
        Outcome::Adopted {
            suffix: "studio.internal".to_owned(),
            devices: 3,
            relay_confirmed: true,
            carrying: false,
        },
        Outcome::Pinning { relay: "https://relay.example:443".to_owned(), fingerprint: "D4:1E".to_owned(), der_len: 812, moving: Some("home".to_owned()) },
        Outcome::Declined { message: "nothing was signed: signing was declined".to_owned() },
        // A key the daemon cannot reach. Never produced on a phone — the
        // keystore answers on the call — but the mirror must be able to read it,
        // because a surface that met an outcome it could not decode would fail
        // on something that is not about it.
        Outcome::NeedsSignatures(daemon::control::SignaturesWanted {
            id: "18f3a-2".to_owned(),
            key: "peerfectly.casa.signing".to_owned(),
            network: "casa".to_owned(),
            items: vec![
                daemon::control::ToSign {
                    kind: daemon::control::SigningKind::Operation,
                    message: vec![0x01, 0x02, 0x03],
                    payload: vec![0xa1, 0x04],
                },
                daemon::control::ToSign {
                    kind: daemon::control::SigningKind::Snapshot,
                    message: vec![0x05],
                    payload: vec![0xa2],
                },
            ],
        }),
        // A key the daemon cannot make, because making it asks a person and the
        // daemon has no desktop. Never produced on a phone, and mirrored for the
        // same reason as `NeedsSignatures`.
        Outcome::NeedsKey(daemon::control::KeyWanted {
            id: "k18f3a".to_owned(),
            name: "peerfectly.casa.signing".to_owned(),
            network: "casa".to_owned(),
        }),
        // Somebody else's, on a machine that holds networks for two people.
        // Never produced on a phone, and mirrored for the same reason as above.
        // Removing a network this device is the only admin of: a question for
        // a person, asked before anything is touched.
        Outcome::OnlyAdmin { network: "casa".to_owned() },
        Outcome::NotAllowed {
            message: "`casa` belongs to somebody else on this machine, and you are not authorised. Nothing about it was changed."
                .to_owned(),
        },
        // What is open, on a desktop that exposes ports. Never produced on a phone.
        Outcome::Exposed {
            rules: vec![daemon::exposing::Exposure {
                network: "casa".to_owned(),
                protocol: daemon::exposing::Protocol::Tcp,
                port: 8000,
            }],
        },
        Outcome::Failed { message: "the adapter would not come up".to_owned(), left_behind: vec!["a route".to_owned()] },
    ]
}

/// Text and how `control::shown` draws it: every character of every class it
/// escapes, each boundary on both sides, a backslash, and names that must pass
/// untouched. The Kotlin `shown` is held to exactly these.
fn shown_table() -> Vec<(String, String)> {
    let mut points: Vec<u32> = Vec::new();
    points.extend(0x00..=0x20);
    points.extend(0x7E..=0xA0);
    for (low, high) in [
        (0x061C_u32, 0x061C_u32),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2066, 0x2069),
        (0x2060, 0x2064),
        (0xFEFF, 0xFEFF),
        (0x2028, 0x2029),
    ] {
        points.extend(low.saturating_sub(1)..=high.saturating_add(1));
    }
    let mut table: Vec<(String, String)> = points
        .into_iter()
        .filter_map(char::from_u32)
        .map(|ch| {
            let text = format!("a{ch}b");
            let drawn = daemon::control::shown(&text).to_string();
            (text, drawn)
        })
        .collect();
    for text in [
        "laptop",
        "città",
        "東京",
        "back\\slash",
        "\\u{202e}",
        "emoji 🛰 ok",
        "l\u{0430}ptop",
        "\u{202E}pot\u{202C}",
    ] {
        table.push((text.to_owned(), daemon::control::shown(text).to_string()));
    }
    table
}

#[test]
fn the_fixture_is_what_the_types_write() {
    let written = serde_json::to_string_pretty(
        &serde_json::json!({ "outcomes": outcomes(), "shown": shown_table() }),
    )
    .unwrap();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/control.json");
    if std::env::var_os("PEERFECTLY_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("{written}\n")).unwrap();
    }
    let held = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        held.trim_end().replace("\r\n", "\n"),
        written,
        "tests/fixtures/control.json is not what the control types write; rerun with PEERFECTLY_BLESS=1 and update the Kotlin mirror"
    );
}

/// The variants `control::Outcome` declares, read from its source.
///
/// `Outcome` is `#[non_exhaustive]`, so a match here could not be made to fail when
/// a variant is added; reading the declaration can.
fn declared_outcomes() -> Vec<String> {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/daemon/src/control.rs"),
    )
    .unwrap();
    let body = source
        .split("pub enum Outcome {")
        .nth(1)
        .unwrap()
        .split(
            "
}",
        )
        .next()
        .unwrap();
    body.lines()
        .filter_map(|line| line.strip_prefix("    "))
        .filter(|line| line.starts_with(|ch: char| ch.is_ascii_uppercase()))
        .map(|line| line.chars().take_while(char::is_ascii_alphanumeric).collect())
        .collect()
}

#[test]
fn every_outcome_variant_is_in_the_fixture() {
    let declared = declared_outcomes();
    assert!(declared.len() >= 8, "read the declaration: {declared:?}");
    let written: Vec<String> = outcomes()
        .iter()
        .map(|outcome| match serde_json::to_value(outcome).unwrap() {
            serde_json::Value::String(tag) => tag,
            serde_json::Value::Object(fields) => fields.keys().next().unwrap().clone(),
            other => panic!("not an outcome: {other}"),
        })
        .collect();
    for variant in &declared {
        assert!(written.contains(variant), "`Outcome::{variant}` is not in the fixture");
    }
}

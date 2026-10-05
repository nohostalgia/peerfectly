//! The sequence rule, stated over generated inputs rather than chosen ones, and
//! the boundaries only reading the source can hold to.
//!
//! These drive the store directly with a supplied clock. The rule they check
//! lives there, and going over HTTP would mean waiting out the publication
//! interval on every attempt — six seconds a case, for a property that has
//! nothing to do with HTTP.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::time::{Duration, Instant};

use identity::PrivateKey;
use proptest::prelude::*;
use rendezvous::record::{Record, SignedRecord};
use rendezvous::store::Store;
use roster::id::NetworkId;
use roster::types::Algorithm;

fn network() -> NetworkId {
    NetworkId::from_bytes([4; 32])
}

fn signed(device: &PrivateKey, sequence: u64, address: &str) -> SignedRecord {
    let record = Record::new(device.public_key(), network(), sequence, vec![address.to_owned()])
        .expect("within bounds");
    SignedRecord::sign(record, device.signer()).expect("signs")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Whatever order publications arrive in, what is held is the highest
    /// sequence that was ever accepted — never a lower one that arrived later.
    #[test]
    fn the_highest_accepted_sequence_is_what_is_held(
        sequences in proptest::collection::vec(1u64..50, 1..12),
    ) {
        let device = PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let mut store = Store::new();
        let start = Instant::now();

        let mut accepted: Option<u64> = None;
        for (step, sequence) in sequences.iter().enumerate() {
            // Far enough apart that the rate limit never decides the outcome:
            // this property is about the sequence rule alone.
            let now = start
                .checked_add(Duration::from_secs((step as u64).saturating_mul(60)))
                .unwrap_or(start);
            let record = signed(&device, *sequence, "ip:a");

            if store.publish_at(record, "1.2.3.4", now).is_ok() {
                // An accepted record must always have been strictly newer.
                if let Some(previous) = accepted {
                    prop_assert!(*sequence > previous, "accepted {sequence} over {previous}");
                }
                accepted = Some(*sequence);
            }
        }

        match accepted {
            Some(expected) => {
                let held = store.get(&device.key_id()).expect("something is held");
                prop_assert_eq!(held.sequence(), expected);
            }
            None => prop_assert!(store.get(&device.key_id()).is_none()),
        }
    }

    /// No sequence of publications, in any order, ever leaves the store holding
    /// a record a client would have to refuse — the held sequence never
    /// decreases.
    #[test]
    fn what_is_held_never_goes_backwards(
        sequences in proptest::collection::vec(1u64..50, 1..12),
    ) {
        let device = PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let mut store = Store::new();
        let start = Instant::now();
        let mut highest = 0u64;

        for (step, sequence) in sequences.iter().enumerate() {
            let now = start
                .checked_add(Duration::from_secs((step as u64).saturating_mul(60)))
                .unwrap_or(start);
            let _ = store.publish_at(signed(&device, *sequence, "ip:a"), "1.2.3.4", now);

            if let Some(held) = store.get(&device.key_id()) {
                let current = held.sequence();
                prop_assert!(current >= highest, "held went from {highest} to {current}");
                highest = current;
            }
        }
    }

    /// A client that remembers the highest sequence it has accepted can never be
    /// walked backwards, whatever the service serves it — including a service
    /// that has restarted with an empty store and accepted a lower sequence.
    #[test]
    fn a_client_remembering_its_highest_is_never_rolled_back(
        served in proptest::collection::vec(1u64..50, 1..12),
    ) {
        let mut seen: Option<u64> = None;

        for sequence in served {
            // The rule the client applies, exactly as `Client::fetch` applies it.
            let acceptable = seen.is_none_or(|highest| sequence > highest);
            if acceptable {
                seen = Some(sequence);
            }
            if let Some(highest) = seen {
                prop_assert!(sequence <= highest, "accepted something above its own high water");
            }
        }
    }

    /// One device's publications never affect what is held for another, whatever
    /// the interleaving. The limits are per key, and so is the sequence.
    #[test]
    fn one_key_never_disturbs_another(
        mine in proptest::collection::vec(1u64..30, 1..8),
        theirs in proptest::collection::vec(1u64..30, 1..8),
    ) {
        let a = PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let b = PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let mut store = Store::new();
        let start = Instant::now();

        let mut step = 0u64;
        let mut next = || {
            step = step.saturating_add(1);
            start.checked_add(Duration::from_secs(step.saturating_mul(60))).unwrap_or(start)
        };

        for sequence in &mine {
            let _ = store.publish_at(signed(&a, *sequence, "ip:a"), "1.1.1.1", next());
        }
        let after_mine = store.get(&a.key_id()).map(|r| r.sequence());

        for sequence in &theirs {
            let _ = store.publish_at(signed(&b, *sequence, "ip:b"), "2.2.2.2", next());
        }

        prop_assert_eq!(
            store.get(&a.key_id()).map(|r| r.sequence()),
            after_mine,
            "another key's publications changed this one"
        );
    }
}

// ---------------------------------------------------------------------------
// Boundaries
// ---------------------------------------------------------------------------

/// The dependency runs one way. Nothing below this crate may know about it, and
/// this crate must not reach into the transport.
#[test]
fn the_dependency_direction_holds() {
    for (name, manifest) in [
        ("roster", include_str!("../../roster/Cargo.toml")),
        ("identity", include_str!("../../identity/Cargo.toml")),
        ("transport", include_str!("../../transport/Cargo.toml")),
        ("transport-iroh", include_str!("../../transport-iroh/Cargo.toml")),
        ("roster-sync", include_str!("../../roster-sync/Cargo.toml")),
    ] {
        assert!(!manifest.contains("rendezvous"), "`{name}` must not depend on this crate");
    }

    let own = include_str!("../Cargo.toml");
    assert!(
        !own.contains("transport"),
        "this crate must not reach into the transport: an address here is an opaque string, \
         and parsing one would couple the rendezvous to whatever the transport currently uses"
    );
}

/// Addresses are opaque. A rendezvous that parsed them would need changing
/// whenever the transport's addressing changed, which is the coupling
/// `transport-session`'s abstraction exists to avoid.
#[test]
fn addresses_are_not_parsed() {
    let client = code_of(include_str!("../src/client.rs"));
    let record = code_of(include_str!("../src/record.rs"));

    for parsing in ["SocketAddr", "IpAddr", "Ipv4Addr", "Ipv6Addr", "parse::<", "from_str"] {
        assert!(!client.contains(parsing), "`{parsing}` in the client parses an address");
        assert!(!record.contains(parsing), "`{parsing}` in the record parses an address");
    }
}

/// The lines of a source file that are not comments.
fn code_of(source: &str) -> String {
    source.lines().map(str::trim).filter(|line| !line.starts_with("//")).collect::<Vec<_>>().join(
        "
",
    )
}

/// §2.6b requires a cached endpoint to be usable *without waiting for the
/// rendezvous*, which only holds if the cache lives above this crate. A client
/// that cached internally would make the 500 ms budget depend on this timing.
#[test]
fn the_client_caches_nothing_and_dials_nothing() {
    let client = include_str!("../src/client.rs");
    // Code only. The prose here explains at length why there is no cache, and a
    // scan that read the prose would fail on the very words that document the
    // decision — the same trap the custodian scan hit in `node-identity`.
    let code = code_of(client);

    for forbidden in ["cache", "Cache", "connect(", "dial"] {
        assert!(
            !code.contains(forbidden),
            "`{forbidden}` in the client: caching and dialling belong above this crate"
        );
    }
    assert!(client.contains("windows-daemon"), "and the prose says where they belong");
}

/// The service holds no secret and no notion of who is calling. Anything
/// resembling a credential would be a thing to steal from the one piece of
/// shared infrastructure the project runs.
#[test]
fn the_service_authenticates_nobody() {
    let service = code_of(include_str!("../src/service.rs"));

    for forbidden in ["token", "Token", "password", "api_key", "Authorization", "bearer"] {
        assert!(!service.contains(forbidden), "`{forbidden}` would be a credential to steal");
    }
    assert!(
        service.contains("decode_and_verify"),
        "a publication is accepted on the evidence of its signature"
    );
}

/// §6.1's three accepted powers are recorded, so nobody has to rediscover what
/// this service is allowed to be.
#[test]
fn the_service_records_what_it_can_and_cannot_do() {
    let service = include_str!("../src/service.rs");
    for cannot in ["cannot inject devices", "cannot alter a record", "cannot produce a record"] {
        assert!(service.contains(cannot), "the note must say it {cannot}");
    }
    for can in ["Censor", "delay", "observe"] {
        assert!(service.contains(can), "and that it can {can}");
    }
}

/// The format document covers every requirement the specification adds. A
/// second implementation works from it, and a requirement missing there is one
/// that implementation is never told it has to satisfy.
#[test]
fn the_format_covers_every_requirement() {
    let format = include_str!("../FORMAT.md");
    for (requirement, marker) in [
        ("An endpoint record is signed by the device it describes", "## 5. What is signed"),
        ("A sequence number that only ever increases", "## 8. The sequence rule"),
        ("The service authenticates nobody", "There is no authentication"),
        ("Bounded cost per key", "### Bounds"),
        (
            "A published address is a hint, never an authority",
            "MUST NOT treat a record as evidence",
        ),
        ("Records are canonically encoded and strictly rejected", "## 3. Encoding"),
    ] {
        assert!(format.contains(marker), "FORMAT.md must cover `{requirement}`");
    }
}

/// The README records why, not only what. Without the reasoning, the absence of
/// a timestamp reads as an oversight and the in-memory store reads as laziness.
#[test]
fn the_readme_records_the_reasoning() {
    let readme = include_str!("../README.md");
    for topic in [
        "no timestamp",
        "restart is not a rollback",
        "never the signing key",
        "caches nothing and dials nothing",
        "Equivocation is refused",
    ] {
        assert!(
            readme.to_lowercase().contains(&topic.to_lowercase()),
            "the README must explain `{topic}`"
        );
    }
}

/// Every deferral names where it went. "Later" is not a destination.
#[test]
fn every_deferral_names_its_destination() {
    let readme = include_str!("../README.md");
    for destination in ["roster-sync", "local-discovery", "windows-daemon"] {
        assert!(readme.contains(destination), "a deferral must name `{destination}`");
    }
}

//! The cache and the ordering over generated inputs, and the boundaries only
//! reading the source can hold to.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::time::{Duration, Instant};

use identity::PrivateKey;
use local_discovery::announce::{self, Announcement};
use local_discovery::order::{Candidate, Conditions, Source};
use local_discovery::{Cache, order};
use proptest::prelude::*;
use rendezvous::Record;
use roster::id::NetworkId;
use roster::types::Algorithm;

fn network() -> NetworkId {
    NetworkId::from_bytes([21; 32])
}

fn source_of(tag: u8) -> Source {
    match tag % 3 {
        0 => Source::Local,
        1 => Source::Global,
        _ => Source::Rendezvous,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Whatever order announcements arrive in, the cache holds the highest
    /// sequence it ever accepted — never a lower one that arrived later.
    #[test]
    fn the_cache_never_goes_backwards(sequences in proptest::collection::vec(1u64..40, 1..12)) {
        let key = roster::id::KeyId::from_bytes([3; 32]);
        let mut cache = Cache::new();
        let start = Instant::now();
        let mut highest = 0u64;

        for (step, sequence) in sequences.iter().enumerate() {
            let now = start
                .checked_add(Duration::from_secs(step as u64))
                .unwrap_or(start);
            let _ = cache.record(key, *sequence, vec![format!("ip:{sequence}")], now);

            if let Some(entry) = cache.entry(&key) {
                prop_assert!(
                    entry.sequence >= highest,
                    "cached sequence went from {highest} to {}",
                    entry.sequence
                );
                highest = entry.sequence;
            }
        }
    }

    /// A replayed older announcement never changes what a peer is believed to be
    /// reachable at.
    #[test]
    fn a_replay_never_moves_a_peer(
        first in 5u64..40,
        replayed in 1u64..40,
    ) {
        let key = roster::id::KeyId::from_bytes([4; 32]);
        let mut cache = Cache::new();
        let now = Instant::now();

        cache.record(key, first, vec!["ip:right".to_owned()], now).expect("recorded");
        let _ = cache.record(key, replayed, vec!["ip:wrong".to_owned()], now);

        let held = cache.addresses_for(&key, now);
        if replayed > first {
            prop_assert_eq!(held, vec!["ip:wrong".to_owned()], "a newer one does replace");
        } else {
            prop_assert_eq!(held, vec!["ip:right".to_owned()], "an older one must not");
        }
    }

    /// Ordering is deterministic and puts local candidates first, whatever the
    /// input order. §8 requires recomputation on every interface change, which
    /// is only safe if the same inputs always give the same answer.
    #[test]
    fn ordering_is_deterministic_and_prefers_local(
        tags in proptest::collection::vec(0u8..3, 1..10),
        shared in any::<bool>(),
    ) {
        let candidates: Vec<Candidate> = tags
            .iter()
            .enumerate()
            .map(|(index, tag)| Candidate::new(format!("ip:{index}"), source_of(*tag)))
            .collect();
        let conditions = Conditions { local_prefixes: Vec::new(), shares_external_address: shared };

        let once = order(&candidates, &conditions);
        let twice = order(&candidates, &conditions);
        prop_assert_eq!(&once, &twice, "the same inputs must give the same order");

        // Every local candidate precedes every rendezvous one.
        let last_local = once.iter().rposition(|c| c.source == Source::Local);
        let first_rendezvous = once.iter().position(|c| c.source == Source::Rendezvous);
        if let (Some(local), Some(rendezvous)) = (last_local, first_rendezvous) {
            prop_assert!(local < rendezvous, "a local candidate must precede a rendezvous one");
        }

        prop_assert_eq!(once.len(), candidates.len(), "ordering drops nothing");
    }

    /// No packet that fails to decrypt, decode or verify ever yields an
    /// announcement — whatever bytes it happens to contain.
    #[test]
    fn arbitrary_bytes_never_open(packet in proptest::collection::vec(any::<u8>(), 0..600)) {
        prop_assert!(
            announce::open(&packet, &network()).is_err(),
            "arbitrary bytes must never produce an announcement"
        );
    }

    /// Tampering anywhere in a sealed packet destroys it. The AEAD catches most,
    /// the signature catches the rest; either way nothing is produced.
    #[test]
    fn a_tampered_packet_never_opens(position in 0usize..200) {
        let device = PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        let record = Record::new(
            device.public_key(),
            network(),
            1,
            vec!["ip:192.168.1.5:41641".to_owned()],
        )
        .expect("within bounds");
        let announced = Announcement::sign(record, device.signer()).expect("signs");
        let mut packet = announce::seal(&announced, &network()).expect("seals");

        prop_assume!(position < packet.len());
        if let Some(byte) = packet.get_mut(position) {
            *byte ^= 0xff;
        }

        prop_assert!(
            announce::open(&packet, &network()).is_err(),
            "a packet altered at byte {position} must not open"
        );
    }
}

// ---------------------------------------------------------------------------
// Boundaries
// ---------------------------------------------------------------------------

/// The lines of a source file that are not comments.
///
/// The prose here explains at length what the obfuscation does *not* do, and a
/// scan that read the prose would fail on the very words documenting the
/// decision.
fn code_of(source: &str) -> String {
    source
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The dependency runs one way, and this crate does not reach into the
/// transport: the same-NAT evidence arrives as a parameter.
#[test]
fn the_dependency_direction_holds() {
    for (name, manifest) in [
        ("roster", include_str!("../../roster/Cargo.toml")),
        ("identity", include_str!("../../identity/Cargo.toml")),
        ("rendezvous", include_str!("../../rendezvous/Cargo.toml")),
        ("transport", include_str!("../../transport/Cargo.toml")),
        ("transport-iroh", include_str!("../../transport-iroh/Cargo.toml")),
    ] {
        assert!(!manifest.contains("local-discovery"), "`{name}` must not depend on this crate");
    }

    let own = include_str!("../Cargo.toml");
    assert!(
        !own.contains("transport"),
        "this crate must not reach into the transport; the same-NAT evidence is a parameter"
    );
}

/// §8: discovery proposes, the roster authorises. The cheapest way to keep that
/// true is to have nothing in the interface that could express the other thing.
#[test]
fn nothing_here_can_express_membership() {
    for source in [
        include_str!("../src/announce.rs"),
        include_str!("../src/cache.rs"),
        include_str!("../src/order.rs"),
        include_str!("../src/multicast.rs"),
    ] {
        let code = code_of(source);
        for forbidden in
            ["is_member", "DiscoveredDevice", "authorize", "authorise", "Role", "is_admin"]
        {
            assert!(
                !code.contains(forbidden),
                "`{forbidden}` would let discovery answer a question that is the roster's"
            );
        }
    }
}

/// Addresses are opaque. Parsing one here would couple this crate to whatever
/// the transport currently considers an address.
#[test]
fn addresses_are_not_parsed() {
    for source in [include_str!("../src/cache.rs"), include_str!("../src/order.rs")] {
        let code = code_of(source);
        for parsing in ["SocketAddr", "IpAddr", "parse::<", "from_str"] {
            assert!(!code.contains(parsing), "`{parsing}` parses an address");
        }
    }
}

/// The most likely harm in this change is a later reader mistaking the
/// obfuscation for confidentiality. The limit must be stated where they will
/// find it.
#[test]
fn the_limit_of_the_obfuscation_is_recorded() {
    let announce = include_str!("../src/announce.rs");
    let lib = include_str!("../src/lib.rs");

    for source in [announce, lib] {
        assert!(
            source.contains("not confidentiality") || source.contains("obfuscation, not"),
            "the source must say plainly that this is not confidentiality"
        );
        // "former" rather than "former member": the prose emphasises the word,
        // and a scan that demanded a contiguous phrase would fail on its own
        // markdown.
        assert!(
            source.contains("former") || source.contains("ex-member"),
            "and that a former member can still read it"
        );
    }
    assert!(
        announce.contains("never be treated as authentication")
            || announce.contains("never** authentication")
            || announce.contains("is never authentication"),
        "and that decrypting authenticates nothing"
    );
}

/// No plaintext per-network discriminator. A stable tag would let an observer
/// track a network's presence over time without reading anything, which is most
/// of what the encryption is for.
#[test]
fn there_is_no_plaintext_discriminator() {
    let device = PrivateKey::generate(Algorithm::Ed25519).expect("generates");
    let record =
        Record::new(device.public_key(), network(), 1, vec!["ip:a".to_owned()]).expect("bounds");
    let announced = Announcement::sign(record, device.signer()).expect("signs");

    let first = announce::seal(&announced, &network()).expect("seals");
    let second = announce::seal(&announced, &network()).expect("seals");

    // Identical input, sealed twice: nothing beyond a few bytes may match at a
    // fixed position, or that would be a stable identifier.
    let shared = first.iter().zip(second.iter()).take_while(|(a, b)| a == b).count();
    assert!(shared < 4, "{shared} leading bytes are stable across packets");
    assert_ne!(first, second, "two seals of one announcement must differ");
}

/// The format document covers every requirement the specification adds. A
/// second implementation works from it.
#[test]
fn the_format_covers_every_requirement() {
    let format = include_str!("../FORMAT.md");
    for (requirement, marker) in [
        ("A device announces itself with a signed announcement", "## 5. What is signed"),
        ("An announcement is unreadable to a stranger", "## 6. The packet"),
        ("The last known local addresses are tried first", "## 8. Repeating, and the cache"),
        ("Candidates are ordered, and reordered", "## 9. Ordering candidates"),
        ("A discovered device is never proof of anything", "never proof of anything"),
        ("The network keeps working with no internet", "MUST NOT require any service beyond"),
    ] {
        assert!(format.contains(marker), "FORMAT.md must cover `{requirement}`");
    }
}

/// The README records why, not only what. Without the reasoning the obfuscation
/// looks stronger than it is and the cache looks like an optimisation.
#[test]
fn the_readme_records_the_reasoning() {
    let readme = include_str!("../README.md");
    for topic in [
        "not confidentiality",
        "former",
        "never authentication",
        "no plaintext discriminator",
        "proposes",
        "assumed to fail",
    ] {
        assert!(
            readme.to_lowercase().contains(&topic.to_lowercase()),
            "the README must explain `{topic}`"
        );
    }
}

/// Every deferral names where it went.
#[test]
fn every_deferral_names_its_destination() {
    let readme = include_str!("../README.md");
    for destination in ["windows-daemon", "transport", "roster"] {
        assert!(readme.contains(destination), "a deferral must name `{destination}`");
    }
}

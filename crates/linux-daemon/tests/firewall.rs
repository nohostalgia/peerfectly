//! The firewall table, written into a real nf_tables from its record.
//!
//! Needs `CAP_NET_ADMIN` and `nft`: `#[ignore]`d, run in the testbed. What these
//! show is that the kernel takes the table as drawn, that exposures are kept in
//! the record and survive the table being lost, and that nothing else is
//! touched; whether a peer's connection is refused or admitted through it is
//! `VERIFICATION.md`'s, between two nodes.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::panic, reason = "a test reports failure by panicking")]

use std::process::Command;

use daemon::exposing::{Exposing as _, Held, Protocol, Rule};
use linux_daemon::firewall::Nftables;
use roster::id::NetworkId;

fn nft(arguments: &[&str]) -> String {
    let output = Command::new("nft").args(arguments).output().unwrap();
    assert!(
        output.status.success(),
        "nft {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn rule(tag: u8, protocol: Protocol, port: u16) -> Rule {
    Rule {
        name: String::new(),
        description: String::new(),
        network: NetworkId::from_bytes([tag; 32]),
        protocol,
        port,
        interface: String::new(),
        remote_addresses: "fd01:203:405:607::/64,100.64.0.0/10".to_owned(),
    }
}

/// One test, in order, because the table is the machine's and tests in
/// parallel would be editing the same one.
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN and nft: run in the testbed"]
async fn the_table_is_drawn_from_the_record_and_survives_being_lost() {
    // Somebody else's table, which must come out of all of this untouched.
    nft(&["add", "table", "inet", "theirs"]);
    nft(&[
        "add",
        "chain",
        "inet",
        "theirs",
        "input",
        "{ type filter hook input priority 10; policy accept; }",
    ]);
    nft(&[
        "add",
        "rule",
        "inet",
        "theirs",
        "input",
        "tcp",
        "dport",
        "2222",
        "accept",
        "comment",
        "\"by hand\"",
    ]);
    let theirs = nft(&["list", "table", "inet", "theirs"]);

    let state = tempfile::tempdir().unwrap();
    let firewall = Nftables::under(state.path());
    firewall.ensure().unwrap();
    let written = nft(&["list", "table", "inet", "peerfectly"]);
    assert!(written.contains("iifname \"peer*\" jump from_networks"), "{written}");
    assert!(written.contains("drop"), "{written}");

    firewall.expose(&rule(1, Protocol::Tcp, 8000)).await.unwrap();
    firewall.expose(&rule(1, Protocol::Tcp, 8000)).await.unwrap();
    firewall.expose(&rule(2, Protocol::Udp, 5353)).await.unwrap();
    let held = firewall.held().await.unwrap();
    assert_eq!(2, held.len(), "exposing twice replaces rather than adds: {held:?}");
    assert!(held.contains(&Held {
        network: NetworkId::from_bytes([1; 32]),
        protocol: Protocol::Tcp,
        port: 8000
    }));
    assert_eq!(
        4,
        nft(&["list", "chain", "inet", "peerfectly", "exposed"]).matches(" accept").count(),
        "two families each"
    );

    // **The kernel forgets; the record does not.** What a boot does to the
    // table is done here by hand, and the next start draws it again.
    nft(&["delete", "table", "inet", "peerfectly"]);
    Nftables::under(state.path()).ensure().unwrap();
    assert_eq!(
        4,
        nft(&["list", "chain", "inet", "peerfectly", "exposed"]).matches(" accept").count(),
        "drawn again"
    );

    assert!(firewall.unexpose(&NetworkId::from_bytes([2; 32]), Protocol::Udp, 5353).await.unwrap());
    assert!(
        !firewall.unexpose(&NetworkId::from_bytes([2; 32]), Protocol::Udp, 5353).await.unwrap(),
        "none left"
    );

    firewall.expose(&rule(3, Protocol::Tcp, 22)).await.unwrap();
    assert_eq!(1, firewall.forget(&NetworkId::from_bytes([1; 32])).await.unwrap());
    assert_eq!(
        1,
        firewall.sweep(&[NetworkId::from_bytes([9; 32])]).await.unwrap(),
        "network 3 was not kept"
    );
    assert!(firewall.held().await.unwrap().is_empty());
    assert_eq!(
        0,
        nft(&["list", "chain", "inet", "peerfectly", "exposed"]).matches(" accept").count()
    );

    // A record nobody can read is refused, and the table is left as it was.
    std::fs::write(state.path().join("exposed.json"), b"not a record").unwrap();
    assert!(firewall.ensure().is_err());

    assert_eq!(
        theirs,
        nft(&["list", "table", "inet", "theirs"]),
        "their table is exactly as it was"
    );
    nft(&["delete", "table", "inet", "theirs"]);
}

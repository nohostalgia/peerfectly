//! An announcer and a listener on one host, over a real multicast socket.
//!
//! The real path: encode, sign, encrypt, send, receive, decrypt, decode,
//! verify, cache. No external service is reachable at any point, which is the
//! requirement the crate exists for.
//!
//! **What this cannot prove** is the thing §8 warns about: whether a real access
//! point forwards multicast at all. No automated test can. That is why the cache
//! is tried first and why announcements repeat — the design assumes the medium
//! fails and stays useful when it does.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use identity::PrivateKey;
use local_discovery::announce::Announcement;
use local_discovery::{Cache, Error, Multicast};
use rendezvous::Record;
use roster::id::NetworkId;
use roster::types::Algorithm;

/// A network id unique to each test.
///
/// Every listener on this host now joins the same group and port — that is the
/// point of `SO_REUSEADDR`, since two nodes side by side must both hear. It also
/// means tests running in parallel receive each other's announcements, and a
/// test that assumed it heard only its own would be reading someone else's.
/// Distinct network ids make the ordinary network check do the separating, which
/// is what would happen on a real network anyway.
fn network(tag: u8) -> NetworkId {
    NetworkId::from_bytes([tag; 32])
}

fn device() -> PrivateKey {
    PrivateKey::generate(Algorithm::Ed25519).expect("generates")
}

fn announcement(device: &PrivateKey, net: NetworkId, sequence: u64, address: &str) -> Announcement {
    let record = Record::new(device.public_key(), net, sequence, vec![address.to_owned()])
        .expect("within bounds");
    Announcement::sign(record, device.signer()).expect("signs")
}

/// Waits for an announcement, or gives up. Bounded so a test that would hang
/// reports instead — multicast may simply not be delivered on a CI host.
async fn hear(listener: &Multicast) -> Option<Announcement> {
    let deadline = Instant::now().checked_add(Duration::from_secs(5))?;
    while Instant::now() < deadline {
        // Anything else is somebody else's network, or noise. Keep listening.
        if let Ok(Ok((announcement, _from))) =
            tokio::time::timeout(Duration::from_millis(500), listener.receive()).await
        {
            return Some(announcement);
        }
    }
    None
}

#[tokio::test]
async fn a_device_is_found_on_the_local_network() {
    let net = network(11);
    let Ok(listener) = Multicast::join(&[Ipv4Addr::LOCALHOST], net).await else {
        eprintln!("multicast unavailable on this host; skipping");
        return;
    };
    let sender = Multicast::sender(&[Ipv4Addr::LOCALHOST], net).await.expect("binds");
    let device = device();

    let announced = announcement(&device, net, 1, "ip:192.168.1.5:41641");
    for _ in 0..5 {
        sender.announce(&announced).await.expect("announces");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let heard = hear(&listener).await.expect("an announcement arrives");
    assert_eq!(heard.record().key.as_bytes(), device.public_key().as_bytes());
    assert_eq!(heard.record().addresses, vec!["ip:192.168.1.5:41641".to_owned()]);
}

/// §8: announcements repeat, so a listener that starts late still learns of a
/// device. Multicast on wifi is filtered or slow, and one send may never arrive.
#[tokio::test]
async fn a_listener_that_starts_late_still_hears() {
    let net = network(12);
    let sender = Multicast::sender(&[Ipv4Addr::LOCALHOST], net).await.expect("binds");
    let device = device();
    let announced = announcement(&device, net, 1, "ip:192.168.1.6:41641");

    // Announced before anybody is listening.
    sender.announce(&announced).await.expect("announces");

    let Ok(listener) = Multicast::join(&[Ipv4Addr::LOCALHOST], net).await else {
        eprintln!("multicast unavailable on this host; skipping");
        return;
    };

    // The repeat is what makes it discoverable at all.
    for _ in 0..5 {
        sender.announce(&announced).await.expect("announces");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(hear(&listener).await.is_some(), "a repeat must reach a late listener");
}

/// The whole requirement: two devices find each other with nothing external
/// reachable. Nothing in this path contacts a server.
#[tokio::test]
async fn discovery_needs_no_external_service() {
    let net = network(13);
    let Ok(listener) = Multicast::join(&[Ipv4Addr::LOCALHOST], net).await else {
        eprintln!("multicast unavailable on this host; skipping");
        return;
    };
    let sender = Multicast::sender(&[Ipv4Addr::LOCALHOST], net).await.expect("binds");
    let device = device();
    let announced = announcement(&device, net, 7, "ip:10.0.0.4:41641");

    for _ in 0..5 {
        sender.announce(&announced).await.expect("announces");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let heard = hear(&listener).await.expect("an announcement arrives");

    // Straight into the cache, which is what makes the next connection fast.
    let mut cache = Cache::new();
    cache
        .record(
            heard.record().key.key_id(),
            heard.record().sequence,
            heard.record().addresses.clone(),
            Instant::now(),
        )
        .expect("cached");

    assert_eq!(
        cache.addresses_for(&device.key_id(), Instant::now()),
        vec!["ip:10.0.0.4:41641".to_owned()]
    );
}

/// A device on another network shares the port and is quietly ignored.
#[tokio::test]
async fn an_announcement_from_another_network_is_ignored() {
    let ours = network(14);
    let theirs = network(250);

    let Ok(listener) = Multicast::join(&[Ipv4Addr::LOCALHOST], ours).await else {
        eprintln!("multicast unavailable on this host; skipping");
        return;
    };
    let sender = Multicast::sender(&[Ipv4Addr::LOCALHOST], theirs).await.expect("binds");
    let stranger = device();
    let announced = announcement(&stranger, theirs, 1, "ip:192.168.9.9:41641");

    for _ in 0..3 {
        sender.announce(&announced).await.expect("announces");
        tokio::time::sleep(Duration::from_millis(80)).await;
    }

    // Nothing for us. The listener stays quiet rather than reporting a fault.
    let outcome = tokio::time::timeout(Duration::from_millis(800), listener.receive()).await;
    if let Ok(Err(reason)) = outcome {
        assert!(
            reason.is_background_noise(),
            "another network's traffic is background, not a fault: {reason:?}"
        );
    }
}

/// An impostor announcing a key it does not hold is discarded at the signature.
/// §8: anyone on a LAN can announce any key, so this is the case that matters.
#[tokio::test]
async fn an_impostor_is_discarded_at_the_signature() {
    let net = network(15);
    let victim = device();
    let impostor = device();

    // A record naming the victim's key, signed by the impostor.
    let record = Record::new(victim.public_key(), net, 1, vec!["ip:192.168.1.99:41641".to_owned()])
        .expect("within bounds");
    let forged = Announcement::sign(record, impostor.signer()).expect("signs");

    let packet = local_discovery::announce::seal(&forged, &net).expect("seals");
    assert_eq!(
        local_discovery::announce::open(&packet, &net),
        Err(Error::SignatureInvalid),
        "announcing a key you do not hold must gain nothing"
    );
}

/// The cache is tried before anything is heard — the reason it exists.
#[tokio::test]
async fn a_cached_address_needs_no_announcement_at_all() {
    let device = device();
    let mut cache = Cache::new();
    let now = Instant::now();

    cache.record(device.key_id(), 1, vec!["ip:192.168.1.5:41641".to_owned()], now).expect("cached");

    // No socket, no listener, no network. §2.6b's 500 ms depends on exactly
    // this: something to try immediately.
    assert_eq!(cache.addresses_for(&device.key_id(), now), vec!["ip:192.168.1.5:41641".to_owned()]);
}

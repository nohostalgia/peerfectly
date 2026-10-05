//! Packets over real QUIC: cut into datagrams, put back together, and never
//! waiting on the stream.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use std::time::Duration;

use common::Fixture;
use transport::session::{Path, Session, Transport};
use transport_iroh::IrohTransport;

/// Two bound endpoints with a session between them, over a relay in this process.
async fn connected() -> (
    IrohTransport,
    IrohTransport,
    Box<dyn Session>,
    Box<dyn Session>,
    Fixture,
    Box<dyn std::any::Any>,
) {
    let (map, url, server) =
        iroh::test_utils::run_relay_server().await.expect("a relay in this process");
    let fixture = Fixture::found(Some(url.as_str()));
    let dialler =
        IrohTransport::bind_trusting_any_relay_certificate(&fixture.founder, fixture.state.clone())
            .await
            .expect("binds");
    let acceptor =
        IrohTransport::bind_trusting_any_relay_certificate(&fixture.joiner, fixture.state.clone())
            .await
            .expect("binds");
    tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(dialler.endpoint().online(), acceptor.endpoint().online())
    })
    .await
    .expect("both endpoints reach the relay");

    let key = acceptor.transport_key();
    let (dialled, accepted) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(dialler.connect(&key), acceptor.accept())
    })
    .await
    .expect("the pair connects");
    (
        dialler,
        acceptor,
        dialled.expect("establishes"),
        accepted.expect("establishes"),
        fixture,
        Box::new((map, server)),
    )
}

/// A packet whose every byte says where it sits and which packet it belongs to,
/// so a partial or spliced delivery cannot pass for a whole one.
fn numbered(number: u16, len: usize) -> Vec<u8> {
    let mut packet = number.to_be_bytes().to_vec();
    packet.extend((2..len).map(|at| u8::try_from((at ^ usize::from(number)) & 0xff).unwrap()));
    packet
}

fn is_whole(packet: &[u8]) -> bool {
    let Some((head, _)) = packet.split_first_chunk::<2>() else { return false };
    let number = u16::from_be_bytes(*head);
    *packet == numbered(number, packet.len())
}

/// Larger than any datagram a UDP path gives QUIC, so both of these cross in
/// pieces: a 1,500-byte packet cannot fit one datagram on an ordinary path, and
/// a 1,280-byte one cannot before the path's MTU has been discovered.
#[tokio::test]
async fn full_size_packets_cross_in_pieces_and_arrive_whole() {
    let (_dialler, _acceptor, dialled, accepted, _fixture, _relay) = connected().await;

    for (number, len) in [(1_u16, 1_280_usize), (2, transport::limits::MAX_PACKET)] {
        let packet = numbered(number, len);
        dialled.send_packet(&packet).await.expect("sends a packet");
        let received = tokio::time::timeout(Duration::from_secs(10), accepted.recv_packet())
            .await
            .expect("arrives")
            .expect("receives");
        assert_eq!(received, packet, "{len} bytes arrive exactly");
    }
}

/// A burst of packets interleaved with payloads: every payload arrives, in
/// order, and no packet arrives partial. Packets may be dropped under the burst;
/// payloads may not.
#[tokio::test]
async fn packets_interleaved_with_payloads_leave_the_payloads_whole_and_in_order() {
    let (_dialler, _acceptor, dialled, accepted, _fixture, _relay) = connected().await;
    let accepted: std::sync::Arc<dyn Session> = std::sync::Arc::from(accepted);

    let reading = {
        let accepted = std::sync::Arc::clone(&accepted);
        tokio::spawn(async move {
            let mut whole = 0_usize;
            while let Ok(Ok(packet)) =
                tokio::time::timeout(Duration::from_secs(3), accepted.recv_packet()).await
            {
                assert!(is_whole(&packet), "a packet arrived partial or spliced");
                whole = whole.saturating_add(1);
            }
            whole
        })
    };

    for number in 0..1_000_u16 {
        dialled.send_packet(&numbered(number, 1_280)).await.expect("sends a packet");
        if number % 10 == 0 {
            dialled.send(&number.to_be_bytes()).await.expect("sends a payload");
        }
    }

    for number in (0..1_000_u16).step_by(10) {
        let payload = tokio::time::timeout(Duration::from_secs(10), accepted.recv())
            .await
            .expect("every payload arrives")
            .expect("receives");
        assert_eq!(payload, number.to_be_bytes().to_vec(), "payloads keep their order");
    }

    let whole = reading.await.expect("the reader finishes");
    assert!(whole > 0, "packets crossed");
    assert!(whole <= 1_000, "no packet was delivered twice or in parts counted as packets");
}

/// Two endpoints on one machine find the direct path, and the transport says so.
#[tokio::test]
async fn a_session_on_loopback_reports_a_direct_path() {
    let (dialler, _acceptor, dialled, _accepted, fixture, _relay) = connected().await;

    let peer = fixture.joiner.device_id();
    let mut last = None;
    for _ in 0..60 {
        // A path carrying nothing gives the connection nothing to migrate.
        let _ = dialled.send_packet(b"keepalive").await;
        last = dialler.path_to(&peer).await;
        if last == Some(Path::Direct) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(last, Some(Path::Direct), "on loopback the session goes direct");
    assert_eq!(dialler.path_to(&fixture.founder.device_id()).await, None, "no session, no path");
}

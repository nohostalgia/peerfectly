//! Enrolment over convesso: a waiting device and an admitting one, through a
//! relay in this process.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::time::Duration;

use identity::NodeIdentity;
use transport_convesso::enrolment::{Admitting, Channel, MAX_MESSAGE, Waiting};
use transport_convesso::fixture::{Network, TestRelay};

const PATIENCE: Duration = Duration::from_secs(20);

/// One exchange: the admitting side's channel and the waiting side's.
async fn exchange(waiting: &Waiting, admitting: &Admitting, relay: &str) -> (Channel, Channel) {
    let key = waiting.transport_key();
    let (reached, accepted) = tokio::time::timeout(PATIENCE, async {
        tokio::join!(admitting.reach(&key, relay), waiting.accept())
    })
    .await
    .expect("the exchange opens");
    (reached.expect("reaches"), accepted.expect("accepts"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exchange_binds_both_ends_to_one_channel() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let joining = NodeIdentity::generate().unwrap();

    let waiting = Waiting::listen(&joining, &relay.written()).await.unwrap();
    tokio::time::timeout(PATIENCE, waiting.online()).await.expect("registers at the relay");
    assert!(waiting.accepted_on_sight().is_none(), "nothing is trusted on sight");
    assert_eq!(waiting.relay(), relay.written());

    let admitting = Admitting::dialling(&network.founder, &network.state).await.unwrap();
    let (mut admin, mut joiner) = exchange(&waiting, &admitting, &relay.written()).await;

    // One channel: the same material, and each side sees the other's key.
    assert_eq!(admin.material().unwrap(), joiner.material().unwrap());
    assert_eq!(admin.material().unwrap().len(), 32);
    assert_eq!(joiner.peer().unwrap(), admin.own(), "the admitting key, as authenticated");
    assert_eq!(admin.peer().unwrap(), joiner.own());
    assert_eq!(joiner.own(), joining.transport_key().public_key(), "the joining device's own key");
    assert_ne!(
        admin.own(),
        network.founder.transport_key().public_key(),
        "the admitting side dials under a key of its own"
    );

    // The waiting side speaks first, as enrolment does; then a roster-sized
    // message back.
    joiner.send(b"hello").await.unwrap();
    assert_eq!(tokio::time::timeout(PATIENCE, admin.receive()).await.unwrap().unwrap(), b"hello");
    let roster: Vec<u8> = (0..MAX_MESSAGE).map(|at| u8::try_from(at % 251).unwrap()).collect();
    admin.send(&roster).await.unwrap();
    let received = tokio::time::timeout(PATIENCE, joiner.receive()).await.unwrap().unwrap();
    assert_eq!(received.len(), MAX_MESSAGE);
    assert_eq!(received, roster, "a message of enrolment's largest size crosses whole");
    assert!(admin.send(&vec![0; MAX_MESSAGE + 1]).await.is_err(), "and no larger");

    // A second exchange, from another admission, is another channel.
    let again = Admitting::dialling(&network.founder, &network.state).await.unwrap();
    let (second, _) = exchange(&waiting, &again, &relay.written()).await;
    assert_ne!(second.material().unwrap(), admin.material().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_nobody_waits_as_is_not_reached() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let admitting = Admitting::dialling(&network.founder, &network.state).await.unwrap();
    let nobody = NodeIdentity::generate().unwrap();
    let reached = tokio::time::timeout(
        Duration::from_secs(30),
        admitting.reach(&nobody.transport_key().public_key(), &relay.written()),
    )
    .await
    .expect("the dial finishes");
    assert!(reached.is_err());
}

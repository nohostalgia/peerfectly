//! What each peer takes, and the frames sent to it cut to that.
//!
//! A peer says in `OPEN` or `ACCEPT` the largest message and frame it takes
//! (`transport_wire::frame::Limits`); until it has, the least every end takes
//! is assumed. A frame larger than its message travels in parts
//! (`transport_wire::parts`), put back together here on the way in.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use convesso_core::identity::PeerId;
use transport_wire::frame::Limits;
use transport_wire::parts::{Joiner, split};

/// One peer: what it said it takes, and the frames of its being put back
/// together.
#[derive(Default)]
struct Peer {
    limits: Option<Limits>,
    joiner: Joiner,
}

/// Every peer's, for one node.
#[derive(Default)]
pub struct Wire {
    peers: std::sync::Mutex<HashMap<PeerId, Peer>>,
    /// Held while one frame's messages go to a peer, so the parts of two
    /// frames never cross on their way: a receiver puts back one frame at a
    /// time where memory is short (a microcontroller), and gives up the one it
    /// was holding when parts of another begin.
    sending: std::sync::Mutex<HashMap<PeerId, std::sync::Arc<tokio::sync::Mutex<()>>>>,
    /// The sequence the next frame sent in parts is given.
    sequence: AtomicU32,
}

impl Wire {
    /// What `peer` takes: what it said, or the least every end takes.
    #[must_use]
    pub fn limits(&self, peer: &PeerId) -> Limits {
        self.peers
            .lock()
            .ok()
            .and_then(|peers| peers.get(peer).and_then(|held| held.limits))
            .unwrap_or(Limits::LEAST)
    }

    /// `peer` said it takes `limits`, in an `OPEN` or an `ACCEPT`.
    pub fn heard(&self, peer: PeerId, limits: Limits) {
        if let Ok(mut peers) = self.peers.lock() {
            peers.entry(peer).or_default().limits = Some(limits.at_least_the_least());
        }
    }

    /// Held while one frame's messages are sent to `peer`.
    pub async fn sending(&self, peer: &PeerId) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = self
            .sending
            .lock()
            .map(|mut held| std::sync::Arc::clone(held.entry(*peer).or_default()))
            .unwrap_or_default();
        lock.lock_owned().await
    }

    /// The messages that carry `frame` to `peer`: the frame where it fits,
    /// else its parts.
    #[must_use]
    pub fn messages(&self, peer: &PeerId, frame: Vec<u8>) -> Vec<Vec<u8>> {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        split(frame, sequence, self.limits(peer).message_len())
    }

    /// A message from `peer`, as a frame's bytes: whole, or put back together
    /// once its last part came, no larger than `largest`; `None` while parts
    /// are still coming.
    #[must_use]
    pub fn join(&self, peer: PeerId, message: &[u8], largest: usize) -> Option<Vec<u8>> {
        let mut peers = self.peers.lock().ok()?;
        let held = peers.entry(peer).or_default();
        held.joiner.take(message, largest).map(std::borrow::Cow::into_owned)
    }

    /// Forgets `peer`: its session with this node ended, and what it said and
    /// was sending with it.
    pub fn forget(&self, peer: &PeerId) {
        if let Ok(mut peers) = self.peers.lock() {
            peers.remove(peer);
        }
        if let Ok(mut sending) = self.sending.lock() {
            sending.remove(peer);
        }
    }
}

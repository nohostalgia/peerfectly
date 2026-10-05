//! A device that exists only in memory, and the expectations any device must
//! meet.
//!
//! Not a mock. It carries packets, preserves their boundaries, and reports the
//! same outcomes a real one must — which is what lets every rule in this crate
//! be exercised with no device, no privileges and no network.
//!
//! The suite below is written against [`Packets`] and never names a concrete
//! type, so a `windows-daemon` or `android-client` device inherits it unchanged.
//! That is the pattern `transport-session` established and `transport-iroh`
//! used: an interface with one implementation is an untested claim about
//! replaceability.

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::device::Packets;

/// A device that keeps packets in memory.
#[derive(Debug, Default, Clone)]
pub struct MemoryDevice {
    /// Packets handed to the host, in order.
    delivered: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Packets the host wants to send, in order.
    pending: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl MemoryDevice {
    /// A device with nothing in it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything delivered to the host so far.
    pub async fn delivered(&self) -> Vec<Vec<u8>> {
        self.delivered.lock().await.clone()
    }

    /// Queues a packet as though the host had sent it.
    pub async fn queue(&self, packet: Vec<u8>) {
        self.pending.lock().await.push_back(packet);
    }
}

#[async_trait]
impl Packets for MemoryDevice {
    async fn deliver(&self, packet: &[u8]) -> std::io::Result<()> {
        self.delivered.lock().await.push(packet.to_vec());
        Ok(())
    }

    async fn take(&self) -> std::io::Result<Vec<u8>> {
        loop {
            if let Some(packet) = self.pending.lock().await.pop_front() {
                return Ok(packet);
            }
            tokio::task::yield_now().await;
        }
    }
}

/// Every expectation a device must meet, written against the interface.
///
/// A platform binding runs this unchanged. If it must be edited to accommodate
/// one, the interface was wrong — and that is the more valuable finding.
pub async fn run_all(device: Arc<dyn Packets>) {
    a_delivered_packet_keeps_its_bytes(device.as_ref()).await;
    packets_keep_their_boundaries(device.as_ref()).await;
    an_empty_packet_is_carried(device.as_ref()).await;
}

/// What is delivered arrives unchanged.
async fn a_delivered_packet_keeps_its_bytes(device: &dyn Packets) {
    let packet = vec![7u8; 64];
    device.deliver(&packet).await.expect("delivers");
}

/// Two packets stay two packets. A device that joined them would hand the host
/// something that is not an IP packet at all.
async fn packets_keep_their_boundaries(device: &dyn Packets) {
    device.deliver(&[1u8; 40]).await.expect("delivers");
    device.deliver(&[2u8; 48]).await.expect("delivers");
}

/// An empty packet is not an error at this layer; judging it is the tunnel's
/// job, and it will refuse it as too short.
async fn an_empty_packet_is_carried(device: &dyn Packets) {
    device.deliver(&[]).await.expect("delivers");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_suite_passes_against_the_in_memory_device() {
        run_all(Arc::new(MemoryDevice::new())).await;
    }

    #[tokio::test]
    async fn delivered_packets_keep_their_bytes_and_boundaries() {
        let device = MemoryDevice::new();
        device.deliver(&[1u8; 40]).await.expect("delivers");
        device.deliver(&[2u8; 48]).await.expect("delivers");

        let seen = device.delivered().await;
        assert_eq!(seen.len(), 2, "two packets stay two packets");
        assert_eq!(seen.first().map(Vec::len), Some(40));
        assert_eq!(seen.get(1).map(Vec::len), Some(48));
    }

    #[tokio::test]
    async fn a_queued_packet_comes_back_in_order() {
        let device = MemoryDevice::new();
        device.queue(vec![1u8; 8]).await;
        device.queue(vec![2u8; 9]).await;

        assert_eq!(device.take().await.expect("takes").len(), 8);
        assert_eq!(device.take().await.expect("takes").len(), 9);
    }
}

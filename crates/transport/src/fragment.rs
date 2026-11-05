//! Packets cut to fit datagrams, and put back together: the rules are
//! `transport_wire::fragment`'s, shared with a microcontroller member; this
//! module keeps them on this machine's clock.

use std::time::{Duration, Instant};

pub use transport_wire::fragment::{
    HEADER, MAX_FRAGMENTS, REASSEMBLY_BYTES, REASSEMBLY_PACKETS, REASSEMBLY_WINDOW_MS, split,
};

/// How long an incomplete packet waits for the rest of its pieces.
pub const REASSEMBLY_WINDOW: Duration = Duration::from_millis(REASSEMBLY_WINDOW_MS);

/// Puts packets back together, within bounds, on this machine's clock.
#[derive(Debug)]
pub struct Reassembler {
    /// When it was made: what its clock counts from.
    since: Instant,
    held: transport_wire::fragment::Reassembler,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    /// A reassembler holding nothing.
    #[must_use]
    pub fn new() -> Self {
        Self { since: Instant::now(), held: transport_wire::fragment::Reassembler::new() }
    }

    /// How many incomplete packets are held.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.held.waiting()
    }

    /// How many bytes incomplete packets hold.
    #[must_use]
    pub const fn held_bytes(&self) -> usize {
        self.held.held_bytes()
    }

    /// Takes one datagram, and returns the packet it completes, if it completes
    /// one.
    pub fn accept(&mut self, datagram: &[u8], now: Instant) -> Option<Vec<u8>> {
        let since = now.saturating_duration_since(self.since);
        self.held.accept(datagram, u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a test reports failure by panicking"
)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn packet(len: usize) -> Vec<u8> {
        (0..len).map(|at| u8::try_from(at % 251).unwrap()).collect()
    }

    fn header(id: u32, index: u8, count: u8, piece: &[u8]) -> Vec<u8> {
        let mut out = id.to_be_bytes().to_vec();
        out.push(index);
        out.push(count);
        out.extend_from_slice(piece);
        out
    }

    #[test]
    fn a_packet_that_fits_is_one_datagram() {
        let pieces = split(9, &packet(1_000), 1_200).unwrap();
        assert_eq!(pieces.len(), 1);
        assert_eq!(pieces[0].len(), 1_000 + HEADER);
        assert_eq!(Reassembler::new().accept(&pieces[0], Instant::now()), Some(packet(1_000)));
    }

    #[test]
    fn a_full_size_packet_is_two_even_pieces_and_comes_back_whole() {
        let pieces = split(1, &packet(1_280), 1_150).unwrap();
        assert_eq!(pieces.len(), 2);
        assert!(pieces.iter().all(|piece| piece.len() <= 1_150));
        assert_eq!(pieces[0].len(), pieces[1].len(), "cut evenly");

        let mut reassembler = Reassembler::new();
        let now = Instant::now();
        assert_eq!(reassembler.accept(&pieces[0], now), None);
        assert_eq!(reassembler.accept(&pieces[1], now), Some(packet(1_280)));
        assert_eq!(reassembler.waiting(), 0);
        assert_eq!(reassembler.held_bytes(), 0);
    }

    #[test]
    fn pieces_out_of_order_still_make_the_packet() {
        let pieces = split(2, &packet(1_500), 400).unwrap();
        assert_eq!(pieces.len(), 4);
        let mut reassembler = Reassembler::new();
        let now = Instant::now();
        for index in [3, 1, 0] {
            assert_eq!(reassembler.accept(&pieces[index], now), None);
        }
        assert_eq!(reassembler.accept(&pieces[2], now), Some(packet(1_500)));
    }

    #[test]
    fn a_packet_missing_a_piece_expires_and_delivers_nothing() {
        let pieces = split(3, &packet(1_280), 700).unwrap();
        let mut reassembler = Reassembler::new();
        let start = Instant::now();
        assert_eq!(reassembler.accept(&pieces[0], start), None);

        let later = start.checked_add(REASSEMBLY_WINDOW + Duration::from_millis(1)).unwrap();
        let other = split(4, b"next", 700).unwrap();
        assert_eq!(reassembler.accept(&other[0], later), Some(b"next".to_vec()));
        assert_eq!(reassembler.waiting(), 0, "the incomplete packet expired");
        assert_eq!(
            reassembler.accept(&pieces[1], later),
            None,
            "and its last piece completes nothing"
        );
    }

    #[test]
    fn a_flood_of_first_pieces_stays_within_the_bounds() {
        let mut reassembler = Reassembler::new();
        let now = Instant::now();
        for id in 0..10_000_u32 {
            let pieces = split(id, &packet(1_500), 400).unwrap();
            assert_eq!(reassembler.accept(&pieces[0], now), None);
            assert!(reassembler.waiting() <= REASSEMBLY_PACKETS);
            assert!(reassembler.held_bytes() <= REASSEMBLY_BYTES);
        }
        // And a complete packet still gets through.
        let whole = split(99_999, &packet(1_280), 700).unwrap();
        assert_eq!(reassembler.accept(&whole[0], now), None);
        assert_eq!(reassembler.accept(&whole[1], now), Some(packet(1_280)));
    }

    #[test]
    fn a_repeated_index_discards_the_packet() {
        let pieces = split(5, &packet(1_280), 700).unwrap();
        let mut reassembler = Reassembler::new();
        let now = Instant::now();
        assert_eq!(reassembler.accept(&pieces[0], now), None);
        assert_eq!(reassembler.accept(&pieces[0], now), None);
        assert_eq!(reassembler.waiting(), 0, "the packet was discarded");
        assert_eq!(reassembler.accept(&pieces[1], now), None, "and nothing of it is delivered");
    }

    #[test]
    fn a_changed_count_discards_the_packet() {
        let mut reassembler = Reassembler::new();
        let now = Instant::now();
        assert_eq!(reassembler.accept(&header(6, 0, 2, b"aa"), now), None);
        assert_eq!(reassembler.accept(&header(6, 1, 3, b"bb"), now), None);
        assert_eq!(reassembler.waiting(), 0);
        assert_eq!(reassembler.accept(&header(6, 1, 2, b"bb"), now), None, "nothing is completed");
    }

    #[test]
    fn an_index_at_or_beyond_its_count_is_refused() {
        let mut reassembler = Reassembler::new();
        let now = Instant::now();
        assert_eq!(reassembler.accept(&header(7, 2, 2, b"x"), now), None);
        assert_eq!(reassembler.accept(&header(7, 0, 0, b"x"), now), None);
        assert_eq!(reassembler.accept(&header(7, 0, 5, b"x"), now), None, "more than the maximum");
        assert_eq!(reassembler.accept(&[1, 2, 3], now), None, "shorter than a header");
        assert_eq!(reassembler.waiting(), 0);
    }

    #[test]
    fn a_packet_needing_too_many_pieces_is_refused() {
        assert!(split(8, &packet(1_500), 300).is_none());
        assert!(split(8, &packet(10), HEADER).is_none(), "a datagram with no room for a byte");
    }

    #[test]
    fn an_empty_packet_is_one_empty_piece() {
        let pieces = split(10, &[], 1_200).unwrap();
        assert_eq!(pieces.len(), 1);
        assert_eq!(Reassembler::new().accept(&pieces[0], Instant::now()), Some(Vec::new()));
    }

    proptest! {
        /// Split, then reassembled in any order, is the packet.
        #[test]
        fn split_then_reassembled_in_any_order_is_the_identity(
            bytes in proptest::collection::vec(any::<u8>(), 0..=1_500),
            datagram in 400_usize..=1_500,
            id in any::<u32>(),
            order in any::<u64>(),
        ) {
            let Some(mut pieces) = split(id, &bytes, datagram) else {
                prop_assert!(bytes.len().div_ceil(datagram.saturating_sub(HEADER)) > MAX_FRAGMENTS);
                return Ok(());
            };
            for piece in &pieces {
                prop_assert!(piece.len() <= datagram);
            }
            // A cheap deterministic shuffle from the generated seed.
            let len = pieces.len();
            for at in 0..len {
                let other = usize::try_from(order.rotate_left(u32::try_from(at).unwrap()).checked_rem(len as u64).unwrap()).unwrap();
                pieces.swap(at, other);
            }
            let mut reassembler = Reassembler::new();
            let now = Instant::now();
            let mut delivered = None;
            for piece in &pieces {
                if let Some(packet) = reassembler.accept(piece, now) {
                    prop_assert!(delivered.is_none(), "delivered once");
                    delivered = Some(packet);
                }
            }
            prop_assert_eq!(delivered, Some(bytes));
            prop_assert_eq!(reassembler.waiting(), 0);
        }
    }
}

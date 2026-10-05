//! Packets cut to fit datagrams, and put back together.
//!
//! A QUIC datagram holds what one QUIC packet on the current path can carry —
//! around 1,150 bytes on a path whose MTU has not been discovered, and never
//! less than a little over a kilobyte. A tunnel packet is up to 1,280 bytes, the
//! least IPv6 allows on a link. So a full-size packet travels as two datagrams,
//! and is delivered only once both have arrived.
//!
//! # The header
//!
//! ```text
//! [ packet id: u32 BE ][ index: u8 ][ count: u8 ][ piece ... ]
//! ```
//!
//! `count` is how many pieces the packet was cut into, `index` which one this is.
//! A packet that fits travels as one piece with `count` 1.
//!
//! # What the receiver holds, and for how long
//!
//! Every datagram comes from an authenticated member, which may still be broken
//! or hostile. A peer that sends the first piece of many packets and never the
//! rest must not make this node hold more than a stated amount: so incomplete
//! packets are bounded in number and in bytes, the oldest go first, and none is
//! kept past a short window. Expiry is checked when a datagram arrives, not by a
//! timer, so an idle session costs nothing.
//!
//! A piece that contradicts the packet it claims — another count, an index
//! already held, an index beyond its count — discards that packet. Guessing which
//! of two contradicting pieces is right would deliver bytes nobody can vouch for.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// The header's width: a four-byte id, an index and a count.
pub const HEADER: usize = 6;

/// The most pieces a packet may be cut into.
///
/// A 1,500-byte packet over the smallest datagram QUIC guarantees needs two;
/// four leaves room for a path that reports less, and refuses anything that
/// would need many.
pub const MAX_FRAGMENTS: usize = 4;

/// Incomplete packets a receiver holds at once.
pub const REASSEMBLY_PACKETS: usize = 64;

/// Bytes of incomplete packets a receiver holds at once.
pub const REASSEMBLY_BYTES: usize = 128 * 1024;

/// How long an incomplete packet waits for the rest of its pieces.
///
/// Far longer than the pieces of one packet take to arrive together, and short
/// enough that what was delivered late would still be of use to the connection
/// inside the tunnel.
pub const REASSEMBLY_WINDOW: Duration = Duration::from_secs(1);

/// Cuts a packet into datagrams no larger than `datagram`.
///
/// `None` when the datagram cannot hold a header and a byte, or when the packet
/// would need more than [`MAX_FRAGMENTS`] pieces at this size.
#[must_use]
pub fn split(id: u32, packet: &[u8], datagram: usize) -> Option<Vec<Vec<u8>>> {
    let room = datagram.checked_sub(HEADER).filter(|room| *room > 0)?;
    let count = packet.len().div_ceil(room).max(1);
    if count > MAX_FRAGMENTS {
        return None;
    }
    // Cut evenly rather than filling each datagram: two similar halves are no
    // more likely to be lost than one full and one small, and neither sits at the
    // path's limit.
    let piece = packet.len().div_ceil(count).max(1);
    let total = u8::try_from(count).ok()?;
    let pieces: Vec<&[u8]> =
        if packet.is_empty() { vec![packet] } else { packet.chunks(piece).collect() };
    pieces
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| {
            let mut datagram = Vec::with_capacity(HEADER.saturating_add(bytes.len()));
            datagram.extend_from_slice(&id.to_be_bytes());
            datagram.push(u8::try_from(index).ok()?);
            datagram.push(total);
            datagram.extend_from_slice(bytes);
            Some(datagram)
        })
        .collect()
}

/// A packet waiting for the rest of its pieces.
struct Partial {
    /// How many pieces it was cut into.
    count: u8,
    /// The pieces held so far, by index.
    pieces: Vec<Option<Vec<u8>>>,
    /// When its first piece arrived.
    first: Instant,
    /// The bytes held for it.
    bytes: usize,
}

/// Puts packets back together, within bounds.
#[derive(Default)]
pub struct Reassembler {
    /// Incomplete packets by id.
    partial: BTreeMap<u32, Partial>,
    /// The bytes all of them hold.
    bytes: usize,
}

impl Reassembler {
    /// A reassembler holding nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many incomplete packets are held.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.partial.len()
    }

    /// How many bytes incomplete packets hold.
    #[must_use]
    pub const fn held_bytes(&self) -> usize {
        self.bytes
    }

    /// Takes one datagram, and returns the packet it completes, if it completes
    /// one.
    pub fn accept(&mut self, datagram: &[u8], now: Instant) -> Option<Vec<u8>> {
        self.expire(now);

        let (header, piece) = datagram.split_first_chunk::<HEADER>()?;
        let [a, b, c, d, index, count] = *header;
        let id = u32::from_be_bytes([a, b, c, d]);
        let (index, count) = (usize::from(index), usize::from(count));

        if count == 0 || count > MAX_FRAGMENTS || index >= count {
            self.forget(id);
            return None;
        }
        if count == 1 {
            // Whole already. An incomplete packet under the same id is
            // contradicted by it, and goes.
            self.forget(id);
            return Some(piece.to_vec());
        }

        if let Some(held) = self.partial.get(&id)
            && (usize::from(held.count) != count
                || held.pieces.get(index).is_none_or(Option::is_some))
        {
            self.forget(id);
            return None;
        }

        if !self.partial.contains_key(&id) {
            self.make_room(piece.len());
            self.partial.insert(
                id,
                Partial {
                    count: u8::try_from(count).ok()?,
                    pieces: vec![None; count],
                    first: now,
                    bytes: 0,
                },
            );
        } else if self.bytes.saturating_add(piece.len()) > REASSEMBLY_BYTES {
            // Room for this piece would mean dropping others; this packet is the
            // one that asked for more, so it is the one that goes.
            self.forget(id);
            return None;
        }

        let held = self.partial.get_mut(&id)?;
        let slot = held.pieces.get_mut(index)?;
        *slot = Some(piece.to_vec());
        held.bytes = held.bytes.saturating_add(piece.len());
        self.bytes = self.bytes.saturating_add(piece.len());

        if held.pieces.iter().all(Option::is_some) {
            let done = self.partial.remove(&id)?;
            self.bytes = self.bytes.saturating_sub(done.bytes);
            return Some(done.pieces.into_iter().flatten().flatten().collect());
        }
        None
    }

    /// Drops every incomplete packet older than the window.
    fn expire(&mut self, now: Instant) {
        let stale: Vec<u32> = self
            .partial
            .iter()
            .filter(|(_, held)| now.saturating_duration_since(held.first) > REASSEMBLY_WINDOW)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            self.forget(id);
        }
    }

    /// Drops the oldest incomplete packets until a new one of `incoming` bytes fits.
    fn make_room(&mut self, incoming: usize) {
        while self.partial.len() >= REASSEMBLY_PACKETS
            || (!self.partial.is_empty() && self.bytes.saturating_add(incoming) > REASSEMBLY_BYTES)
        {
            let Some(oldest) =
                self.partial.iter().min_by_key(|(_, held)| held.first).map(|(id, _)| *id)
            else {
                return;
            };
            self.forget(oldest);
        }
    }

    /// Drops one incomplete packet, if it is held.
    fn forget(&mut self, id: u32) {
        if let Some(held) = self.partial.remove(&id) {
            self.bytes = self.bytes.saturating_sub(held.bytes);
        }
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

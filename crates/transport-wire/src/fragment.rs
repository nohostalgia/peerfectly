//! Packets cut to fit datagrams, and put back together.
//!
//! A datagram holds what the connectivity layer can carry in one packet on its
//! path, and that is less than the largest tunnel packet. A packet that does not
//! fit travels as several datagrams, and is delivered only once all of them have
//! arrived.
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

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

/// The header's width: a four-byte id, an index and a count.
pub const HEADER: usize = 6;

/// The most pieces a packet may be cut into.
///
/// A 1,500-byte packet over the datagrams `transport-convesso` sends needs two;
/// four leaves room for a path that reports less, and refuses anything that
/// would need many.
pub const MAX_FRAGMENTS: usize = 4;

/// Incomplete packets a receiver holds at once.
pub const REASSEMBLY_PACKETS: usize = 64;

/// Bytes of incomplete packets a receiver holds at once.
pub const REASSEMBLY_BYTES: usize = 128 * 1024;

/// How long an incomplete packet waits for the rest of its pieces, in
/// milliseconds.
///
/// Far longer than the pieces of one packet take to arrive together, and short
/// enough that what was delivered late would still be of use to the connection
/// inside the tunnel.
pub const REASSEMBLY_WINDOW_MS: u64 = 1_000;

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
#[derive(Debug)]
struct Partial {
    /// How many pieces it was cut into.
    count: u8,
    /// The pieces held so far, by index.
    pieces: Vec<Option<Vec<u8>>>,
    /// When its first piece arrived, in milliseconds.
    first: u64,
    /// The bytes held for it.
    bytes: usize,
}

/// Puts packets back together, within bounds.
#[derive(Debug, Default)]
pub struct Reassembler {
    /// Incomplete packets by id.
    partial: BTreeMap<u32, Partial>,
    /// The bytes all of them hold.
    bytes: usize,
}

impl Reassembler {
    /// A reassembler holding nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self { partial: BTreeMap::new(), bytes: 0 }
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

    /// Takes one datagram arriving at `now`, in milliseconds, and returns the
    /// packet it completes, if it completes one.
    pub fn accept(&mut self, datagram: &[u8], now: u64) -> Option<Vec<u8>> {
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
    fn expire(&mut self, now: u64) {
        let stale: Vec<u32> = self
            .partial
            .iter()
            .filter(|(_, held)| now.saturating_sub(held.first) > REASSEMBLY_WINDOW_MS)
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

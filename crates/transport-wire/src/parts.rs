//! A frame too large for the message its receiver takes travels in parts.
//!
//! A computer takes a payload of the interface's largest size in one convesso
//! message; a microcontroller takes 2 KB. So a frame larger than what its
//! receiver says it takes ([`crate::frame::Limits`]) is cut into `PART`s, each
//! carrying a piece of the frame's bytes, the last marked; the receiver puts
//! them back together and reads the frame. Messages from one peer arrive in
//! order, so the pieces of a frame do; two frames sent at once are told apart by
//! the sequence their sender gave each.
//!
//! What a receiver holds is bounded: [`MAX_ASSEMBLING`] frames at once (fewer
//! where it says so, [`Joiner::holding`]), each no larger than the frame it
//! says it takes. A frame that would grow past that is dropped whole, as a
//! frame of an unknown kind is. And from a peer it does not yet speak to, a
//! receiver puts back together no frame larger than [`MAX_OPENING`]: an `OPEN`
//! of the largest size and nothing else, so a stranger makes it hold little.

use alloc::borrow::Cow;
use alloc::vec::Vec;

use crate::frame::{PART, PART_HEADER, SessionId, id_and_rest};

/// How many frames a receiver puts back together at once, from one peer.
pub const MAX_ASSEMBLING: usize = 4;

/// The messages that carry `frame`, a frame's bytes, to a receiver taking
/// messages of `message` bytes at most: the frame itself where it fits, else
/// its parts, in order, marked with `sequence`.
///
/// `message` below a part's header and one byte is read as that.
#[must_use]
pub fn split(frame: Vec<u8>, sequence: u32, message: usize) -> Vec<Vec<u8>> {
    if frame.len() <= message {
        return Vec::from([frame]);
    }
    // The id follows the kind, and in an `OPEN` the version.
    let at: usize = if frame.first() == Some(&crate::frame::OPEN) { 2 } else { 1 };
    let id = frame
        .get(at..at.saturating_add(8))
        .and_then(|id| <[u8; 8]>::try_from(id).ok())
        .unwrap_or_default();
    split_by(&frame, id, sequence, message)
}

/// The parts of `frame`, each carrying `id`.
fn split_by(frame: &[u8], id: [u8; 8], sequence: u32, message: usize) -> Vec<Vec<u8>> {
    let room = message.saturating_sub(PART_HEADER).max(1);
    let count = frame.len().div_ceil(room);
    frame
        .chunks(room)
        .enumerate()
        .map(|(index, piece)| {
            let mut part = Vec::with_capacity(PART_HEADER.saturating_add(piece.len()));
            part.push(PART);
            part.extend_from_slice(&id);
            part.extend_from_slice(&sequence.to_be_bytes());
            part.push(u8::from(index.saturating_add(1) == count));
            part.extend_from_slice(piece);
            part
        })
        .collect()
}

/// A frame being put back together.
#[derive(Debug, Clone)]
struct Assembling {
    id: SessionId,
    sequence: u32,
    /// What came so far; `None` once it grew past the largest frame, its
    /// remaining parts then dropped.
    bytes: Option<Vec<u8>>,
}

/// The largest frame put back together for a peer a receiver does not yet
/// speak to: an `OPEN` whose evidence is a leaf with every field at its
/// largest (about 3.5 KB, `roster::limits`) and its proof, with room.
pub const MAX_OPENING: usize = 8 * 1024;

/// Whether `message` is a part of a frame, not a frame.
#[must_use]
pub fn is_part(message: &[u8]) -> bool {
    message.first() == Some(&PART)
}

/// What a receiver puts back together, from one peer.
#[derive(Debug, Clone)]
pub struct Joiner {
    assembling: Vec<Assembling>,
    /// How many frames it puts back together at once.
    room: usize,
}

impl Default for Joiner {
    fn default() -> Self {
        Self::new()
    }
}

impl Joiner {
    /// A joiner holding nothing, putting back [`MAX_ASSEMBLING`] frames at
    /// once.
    #[must_use]
    pub const fn new() -> Self {
        Self::holding(MAX_ASSEMBLING)
    }

    /// A joiner putting back `room` frames at once, at least one: fewer where
    /// memory is short.
    #[must_use]
    pub const fn holding(room: usize) -> Self {
        let room = if room == 0 { 1 } else { room };
        Self { assembling: Vec::new(), room }
    }

    /// Takes a message from the peer: a frame's bytes, whole, as they came or
    /// put back together from its parts; or `None` while parts are still
    /// coming, or for a part that is not one, or a frame larger than `largest`.
    pub fn take<'a>(&mut self, message: &'a [u8], largest: usize) -> Option<Cow<'a, [u8]>> {
        let Some((&PART, rest)) = message.split_first() else {
            return Some(Cow::Borrowed(message));
        };
        let (id, rest) = id_and_rest(rest)?;
        let (sequence, rest) = rest.split_at_checked(4)?;
        let sequence = u32::from_be_bytes(sequence.try_into().ok()?);
        let (&last, piece) = rest.split_first()?;
        let at = match self
            .assembling
            .iter()
            .position(|held| held.id == id && held.sequence == sequence)
        {
            Some(at) => at,
            None => {
                if self.assembling.len() >= self.room {
                    // The oldest is given up: a sender that left one half sent
                    // does not hold the receiver's room for ever.
                    self.assembling.remove(0);
                }
                self.assembling.push(Assembling { id, sequence, bytes: Some(Vec::new()) });
                self.assembling.len().saturating_sub(1)
            }
        };
        let held = self.assembling.get_mut(at)?;
        if let Some(bytes) = &mut held.bytes {
            if bytes.len().saturating_add(piece.len()) > largest {
                held.bytes = None;
            } else {
                bytes.extend_from_slice(piece);
            }
        }
        if last == 0 {
            return None;
        }
        let done = self.assembling.remove(at);
        done.bytes.filter(|bytes| frame_id(bytes) == Some(id)).map(Cow::Owned)
    }

    /// Whether nothing is being put back together.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.assembling.is_empty()
    }
}

/// The id a frame's bytes name, where they name one.
fn frame_id(bytes: &[u8]) -> Option<SessionId> {
    let (&kind, rest) = bytes.split_first()?;
    let rest = if kind == crate::frame::OPEN { rest.get(1..)? } else { rest };
    id_and_rest(rest).map(|(id, _)| id)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "a test reports failure by panicking"
)]
mod tests {
    use alloc::vec;

    use proptest::prelude::*;

    use super::*;
    use crate::frame::{Frame, Limits, VERSION};

    fn joined(messages: &[Vec<u8>], largest: usize) -> Vec<Vec<u8>> {
        let mut joiner = Joiner::new();
        messages
            .iter()
            .filter_map(|message| joiner.take(message, largest).map(|bytes| bytes.into_owned()))
            .collect()
    }

    #[test]
    fn a_frame_that_fits_travels_whole() {
        let frame = Frame::Payload { id: 3, bytes: vec![1; 100] }.encode();
        let messages = split(frame.clone(), 0, 2_048);
        assert_eq!(messages, vec![frame.clone()]);
        assert_eq!(joined(&messages, 100_000), vec![frame]);
    }

    #[test]
    fn a_frame_too_large_travels_in_parts_each_within_the_message() {
        let frame = Frame::Roots { id: 3, roots: vec![7; 10_000] }.encode();
        let messages = split(frame.clone(), 9, 2_048);
        assert!(messages.len() > 1);
        assert!(messages.iter().all(|message| message.len() <= 2_048));
        assert_eq!(joined(&messages, 100_000), vec![frame]);
    }

    #[test]
    fn an_open_travels_in_parts_too() {
        let frame = Frame::Open {
            version: VERSION,
            id: 77,
            limits: Limits::LEAST,
            evidence: vec![5; 5_000],
        }
        .encode();
        let messages = split(frame.clone(), 1, 2_048);
        assert!(messages.len() > 1);
        let back = joined(&messages, 100_000);
        assert_eq!(back, vec![frame]);
        assert!(matches!(Frame::decode(&back[0]), Some(Frame::Open { id: 77, .. })));
    }

    #[test]
    fn two_frames_sent_at_once_are_told_apart() {
        let one = Frame::Payload { id: 3, bytes: vec![1; 5_000] }.encode();
        let two = Frame::Payload { id: 3, bytes: vec![2; 5_000] }.encode();
        let first = split(one.clone(), 1, 2_048);
        let second = split(two.clone(), 2, 2_048);
        let mut interleaved = Vec::new();
        for index in 0..first.len().max(second.len()) {
            interleaved.extend(first.get(index).cloned());
            interleaved.extend(second.get(index).cloned());
        }
        assert_eq!(joined(&interleaved, 100_000), vec![one, two]);
    }

    #[test]
    fn a_frame_larger_than_the_receiver_takes_is_dropped_whole() {
        let large = Frame::Payload { id: 3, bytes: vec![1; 10_000] }.encode();
        let small = Frame::Payload { id: 4, bytes: vec![2; 3_000] }.encode();
        let mut messages = split(large, 1, 2_048);
        messages.extend(split(small.clone(), 2, 2_048));
        assert_eq!(joined(&messages, 5_000), vec![small]);
    }

    #[test]
    fn a_part_naming_another_session_than_its_frame_is_dropped() {
        let frame = Frame::Payload { id: 3, bytes: vec![1; 5_000] }.encode();
        let mut messages = split(frame, 1, 2_048);
        // The parts say 3; make them say 4, the frame inside still 3.
        for message in &mut messages {
            message[8] = 4;
        }
        assert!(joined(&messages, 100_000).is_empty());
    }

    #[test]
    fn what_is_held_is_bounded() {
        let mut joiner = Joiner::new();
        for sequence in 0..100_u32 {
            let parts =
                split(Frame::Payload { id: 3, bytes: vec![1; 5_000] }.encode(), sequence, 2_048);
            assert!(joiner.take(&parts[0], 100_000).is_none());
        }
        assert!(joiner.assembling.len() <= MAX_ASSEMBLING);
    }

    #[test]
    fn a_joiner_holding_one_puts_back_one_frame_at_a_time() {
        let mut joiner = Joiner::holding(1);
        let one = split(Frame::Payload { id: 3, bytes: vec![1; 5_000] }.encode(), 1, 2_048);
        let two = split(Frame::Payload { id: 3, bytes: vec![2; 5_000] }.encode(), 2, 2_048);
        assert!(joiner.take(&one[0], 100_000).is_none());
        // A second frame begun gives up the first.
        assert!(joiner.take(&two[0], 100_000).is_none());
        assert_eq!(joiner.assembling.len(), 1);
        for part in &one[1..] {
            assert!(joiner.take(part, 100_000).is_none(), "the first was given up");
        }
        assert!(joiner.assembling.len() <= 1);
    }

    /// From a stranger, an opening of the largest size comes back, and a larger
    /// frame does not.
    #[test]
    fn an_opening_fits_what_a_stranger_may_send_in_parts() {
        let opening = Frame::Open {
            version: VERSION,
            id: 9,
            limits: Limits::LEAST,
            evidence: vec![5; MAX_OPENING - 64],
        }
        .encode();
        assert_eq!(joined(&split(opening.clone(), 1, 2_048), MAX_OPENING), vec![opening]);
        let larger = Frame::Payload { id: 9, bytes: vec![5; MAX_OPENING] }.encode();
        assert!(joined(&split(larger, 2, 2_048), MAX_OPENING).is_empty());
    }

    proptest! {
        /// Whatever arrives, the joiner answers and does not panic.
        #[test]
        fn arbitrary_messages_never_panic(
            messages in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 0..16)
        ) {
            let mut joiner = Joiner::new();
            for message in &messages {
                let _ = joiner.take(message, 1_000);
            }
        }

        /// Any frame of any size comes back whole, through any message size.
        #[test]
        fn any_frame_comes_back_through_any_message_size(
            size in 0_usize..20_000,
            message in 16_usize..4_096,
            sequence in any::<u32>(),
        ) {
            let frame = Frame::Payload { id: 9, bytes: vec![3; size] }.encode();
            let messages = split(frame.clone(), sequence, message);
            prop_assert!(messages.iter().all(|sent| sent.len() <= message.max(PART_HEADER + 1)));
            prop_assert_eq!(joined(&messages, 100_000), vec![frame]);
        }
    }
}

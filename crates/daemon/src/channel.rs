//! What a payload on a session is.
//!
//! A session carries roster reconciliation as payloads and tunnel packets as
//! packets, which the transport keeps apart: a packet never waits behind a
//! payload, and a payload is never lost. So the payload channel carries one
//! protocol today, and each payload still says which, so a later one can join it
//! without a payload of one being read as the other.
//!
//! # Why one byte and no more
//!
//! This tag is **inside** an authenticated session. The transport has already
//! established which device is speaking and encrypted the channel; the tag says
//! only what to do with the bytes, and a peer that lies about it can at worst
//! feed roster bytes to the packet path or the reverse, where both refuse it.
//!
//! So no domain separation and no signature here — the rule in `DESIGN.md` §0
//! covers what is *signed*, and nothing on this channel is. Adding a signature
//! would suggest the tag carries authority it does not have.
//!
//! # An unknown tag is refused, never guessed
//!
//! The same rule the roster applies to unknown algorithms. A tag this build does
//! not know might belong to a later version of the protocol carrying something
//! that matters, and treating it as one of the two we do know is how a node acts
//! on a message it did not understand.

/// What a payload on a session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Channel {
    /// Roster reconciliation, for `roster-sync`.
    Roster,
    /// "I contacted you as one of my neighbours."
    ///
    /// Sent when a device opens contact with a neighbour it chose, so that the
    /// neighbour pushes to it too. The receiver checks the claim against the
    /// roster before believing it; see `neighbours::claim_holds`.
    Neighbour,
}

impl Channel {
    /// The byte that names this channel.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Roster => 1,
            Self::Neighbour => 3,
        }
    }

    /// The channel a tag names, if this build knows it.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        // 2 was a tunnel packet, when packets travelled as payloads. It is not
        // reused: a payload tagged 2 comes from a build that sends packets on the
        // stream, and is refused rather than read as anything else.
        match tag {
            1 => Some(Self::Roster),
            3 => Some(Self::Neighbour),
            _ => None,
        }
    }
}

/// Wraps a payload for sending.
#[must_use]
pub fn frame(channel: Channel, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len().saturating_add(1));
    out.push(channel.tag());
    out.extend_from_slice(payload);
    out
}

/// Reads a payload that arrived.
///
/// `None` for an empty payload or a tag this build does not know. Refused rather
/// than guessed at: a tag from a later version of the protocol might carry
/// something that matters, and acting on it as though it were one of ours is
/// acting on a message we did not understand.
#[must_use]
pub fn unframe(bytes: &[u8]) -> Option<(Channel, &[u8])> {
    let (tag, payload) = bytes.split_first()?;
    Some((Channel::from_tag(*tag)?, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_roster_payload_round_trips() {
        let payload = b"some bytes";
        let framed = frame(Channel::Roster, payload);
        assert_eq!(unframe(&framed), Some((Channel::Roster, payload.as_slice())));
    }

    /// Packets left the payload channel. A payload still tagged as one is not a
    /// packet any more, and is not read as roster either.
    #[test]
    fn a_payload_tagged_as_a_packet_is_refused() {
        assert_eq!(Channel::from_tag(2), None);
        assert_eq!(unframe(&[2, 0x60, 0, 0]), None);
    }

    /// The same rule the roster applies to an unknown algorithm: refuse, because
    /// what you cannot parse might be the thing that mattered.
    #[test]
    fn an_unknown_tag_is_refused_rather_than_guessed_at() {
        for tag in [0u8, 2, 4, 9, 255] {
            assert_eq!(Channel::from_tag(tag), None, "tag {tag}");
            assert_eq!(unframe(&[tag, 1, 2, 3]), None, "tag {tag}");
        }
    }

    #[test]
    fn an_empty_payload_is_not_a_channel() {
        assert_eq!(unframe(&[]), None);
    }

    #[test]
    fn a_channel_with_no_body_is_still_that_channel() {
        assert_eq!(unframe(&frame(Channel::Roster, &[])), Some((Channel::Roster, [].as_slice())));
    }

    /// A tag is not a claim about who is speaking — the session settled that —
    /// so the worst a lying peer achieves is feeding one path bytes the other
    /// path would have refused anyway.
    #[test]
    fn the_tag_carries_no_authority() {
        let code = crate::code_of(include_str!("channel.rs"));
        for forbidden in ["sign", "verify", "DeviceId", "PublicKey"] {
            assert!(!code.contains(forbidden), "`{forbidden}` would suggest the tag decides who");
        }
    }
}

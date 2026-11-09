//! The frames, as `transport_wire::frame` writes them, and the sizes this
//! binding takes on a computer.

use convesso_stream::config::StreamConfig;

pub use transport_wire::frame::*;

convesso_stream::config! {
    /// The stream configuration every computer of this binding runs: the
    /// server's, with a largest message that holds the interface's largest
    /// payload and its header, so a payload to another computer is one message.
    pub Stream: Server { max_message: transport::limits::MAX_PAYLOAD + PAYLOAD_HEADER }
}

/// The largest convesso message the node carries.
pub const MAX_MESSAGE: usize = <Stream as StreamConfig>::MAX_MESSAGE;

/// The most bytes of roots one `ROOTS` frame carries, to a peer taking frames
/// of this node's size.
pub const MAX_ROOTS: usize = MAX_MESSAGE - PAYLOAD_HEADER;

/// What this node takes, and says it takes: a message of [`MAX_MESSAGE`], and
/// a frame of the same size.
#[allow(
    clippy::cast_possible_truncation,
    reason = "MAX_MESSAGE is a quarter of a megabyte, checked below to fit"
)]
pub const OWN: Limits = Limits { message: MAX_MESSAGE as u32, frame: MAX_MESSAGE as u32 };

const _: () = assert!(MAX_MESSAGE <= u32::MAX as usize, "a message length fits its field");

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// The configuration has room for the largest payload and its header, so a
    /// payload to another computer is never cut.
    #[test]
    fn a_payload_of_the_largest_size_is_one_message() {
        let payload = vec![7u8; transport::limits::MAX_PAYLOAD];
        let message = Frame::Payload { id: 9, bytes: payload.clone() }.encode();
        assert_eq!(message.len(), MAX_MESSAGE);
        assert_eq!(
            transport_wire::parts::split(message.clone(), 0, OWN.message_len()),
            vec![message.clone()]
        );
        assert_eq!(Frame::decode(&message), Some(Frame::Payload { id: 9, bytes: payload }));
    }

    /// What a computer takes is at least what every end takes.
    #[test]
    fn this_node_takes_at_least_the_least() {
        assert_eq!(OWN.at_least_the_least(), OWN);
    }
}

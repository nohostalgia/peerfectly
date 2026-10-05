//! How a request and its answer travel on the control channel: one line of JSON
//! each way, over whatever stream the platform provides — a named pipe on
//! Windows, a socket on Linux.
//!
//! Here, beside the protocol's types, so both ends use the same framing and
//! neither platform has its own copy of it.

use std::io;

use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _,
};

use crate::limits;

/// Sends a request and reads the reply.
///
/// One line out, one line back. Neither side closes anything, which is exactly
/// what the first version got wrong.
///
/// # Errors
///
/// When the stream fails, or the reply is not what was expected.
pub async fn ask<S, Q, A>(stream: &mut S, request: &Q) -> io::Result<A>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Q: serde::Serialize,
    A: serde::de::DeserializeOwned,
{
    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    stream.write_all(&line).await?;
    stream.flush().await?;

    let mut reply = String::new();
    let mut reader = tokio::io::BufReader::new(stream);
    reader.read_line(&mut reply).await?;

    if reply.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the daemon closed the connection without answering",
        ));
    }
    serde_json::from_str(reply.trim()).map_err(io::Error::other)
}

/// Reads one request.
///
/// Separate from writing the answer because **the daemon has to do something
/// between them**: who is calling can only be read off the channel once the
/// client's first bytes have arrived, so establishing it belongs after this and
/// before the handler.
///
/// # Errors
///
/// When the stream fails, nothing is sent, or what is sent is not a request.
pub async fn read_request<S, Q>(stream: &mut S) -> io::Result<Q>
where
    S: AsyncRead + Unpin,
    Q: serde::de::DeserializeOwned,
{
    let mut request = String::new();
    let read = {
        // **Bounded before it is read, not measured after.** `take` stops the
        // reader at the limit, so a client that sends a gigabyte finds the
        // daemon holding `MAX_CONTROL_REQUEST` of it and nothing more.
        let mut reader =
            tokio::io::BufReader::new((&mut *stream).take(limits::MAX_CONTROL_REQUEST));
        reader.read_line(&mut request).await?
    };

    if request.trim().is_empty() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no request"));
    }
    // A line that reached the limit without ending is a line that has not
    // finished, and what follows it is not going to be read — so the request is
    // refused rather than parsed from a piece of itself.
    if read as u64 >= limits::MAX_CONTROL_REQUEST && !request.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "a request longer than {} bytes is not one this protocol carries; \
                 nothing was read past that",
                limits::MAX_CONTROL_REQUEST
            ),
        ));
    }
    serde_json::from_str(request.trim()).map_err(io::Error::other)
}

/// The same, given up on if nothing arrives.
///
/// A client that connects and falls silent costs a connection and a task for as
/// long as it cares to. Dropping it is the whole handling: there is nothing to
/// answer and nothing was begun.
///
/// # Errors
///
/// When the stream fails, nothing is sent in time, or what is sent is not a
/// request or is larger than the protocol carries.
pub async fn read_request_in_time<S, Q>(stream: &mut S) -> io::Result<Q>
where
    S: AsyncRead + Unpin,
    Q: serde::de::DeserializeOwned,
{
    match tokio::time::timeout(limits::SAYS_SOMETHING_WITHIN, read_request(stream)).await {
        Ok(read) => read,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "a client connected and said nothing; it was dropped",
        )),
    }
}

/// Writes one answer.
///
/// # Errors
///
/// When the stream fails or the answer will not serialise.
pub async fn write_answer<S, A>(stream: &mut S, answer: &A) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
    A: serde::Serialize,
{
    let mut line = serde_json::to_vec(answer)?;
    line.push(b'\n');
    stream.write_all(&line).await?;
    stream.flush().await
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// A request out and an answer back, over any stream.
    #[tokio::test]
    async fn a_request_goes_out_and_an_answer_comes_back() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let serving = tokio::spawn(async move {
            let asked: String = read_request(&mut server).await.unwrap();
            write_answer(&mut server, &format!("answered {asked}")).await.unwrap();
        });

        let answered: String = ask(&mut client, &"status".to_owned()).await.unwrap();
        serving.await.unwrap();
        assert_eq!("answered status", answered);
    }

    /// **A request past the bound is refused, and nothing past it is read.**
    #[tokio::test]
    async fn an_oversized_request_is_refused() {
        let (mut client, mut server) = tokio::io::duplex(1 << 20);
        let long = vec![b'x'; usize::try_from(limits::MAX_CONTROL_REQUEST).unwrap() + 10];
        let sending = tokio::spawn(async move {
            let _ = client.write_all(&long).await;
            client
        });

        let refused = read_request::<_, String>(&mut server).await;
        assert_eq!(io::ErrorKind::InvalidData, refused.unwrap_err().kind());
        drop(sending);
    }

    /// **A client that says nothing is dropped**, within the wait everybody uses.
    #[tokio::test(start_paused = true)]
    async fn a_client_that_says_nothing_is_dropped() {
        let (_client, mut server) = tokio::io::duplex(64);
        let dropped = read_request_in_time::<_, String>(&mut server).await;
        assert_eq!(io::ErrorKind::TimedOut, dropped.unwrap_err().kind());
    }

    /// A connection closed with nothing said is not a request.
    #[tokio::test]
    async fn a_closed_connection_is_no_request() {
        let (client, mut server) = tokio::io::duplex(64);
        drop(client);
        let none = read_request::<_, String>(&mut server).await;
        assert_eq!(io::ErrorKind::UnexpectedEof, none.unwrap_err().kind());
    }
}

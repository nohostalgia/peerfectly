//! The service. Two routes, no authentication, no accounts.
//!
//! §2.8 is explicit that the signatures do everything. This holds no secret, so
//! there is nothing in it to steal, nothing to phish, and no credential whose
//! loss would mean anything.
//!
//! # What it cannot do
//!
//! Per §6.1, a compromised instance of this service:
//!
//! - **cannot inject devices.** Membership is the roster's. A record is not
//!   evidence of it, and a client that connects to an address published for an
//!   unknown key gets the transport's ordinary membership refusal.
//! - **cannot alter a record.** It stores the exact bytes the device signed and
//!   serves them back; anything else fails verification at the client.
//! - **cannot produce a record that verifies.** It holds no key any client would
//!   accept.
//!
//! # What it can do
//!
//! **Censor, delay, and observe.** Those are accepted, and they are why a
//! network must keep working when this is unreachable — §8 is blunt about it:
//! failing to connect while standing half a metre from a node, because a server
//! was down, would be an absurd failure for a product sold on sovereignty.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use roster::id::KeyId;
use tokio::sync::Mutex;

use crate::error::{Error, Limit};
use crate::limits;
use crate::record::SignedRecord;
use crate::store::Store;

/// The store, shared across requests.
type Shared = Arc<Mutex<Store>>;

/// Builds the router.
///
/// Serve it with `into_make_service_with_connect_info::<SocketAddr>()`, because
/// the per-source key limit needs the peer address — the only thing here decided
/// by something the service observes rather than something a record proves.
pub fn router(store: Shared) -> Router {
    Router::new()
        .route("/r/{key}", get(fetch).put(publish))
        .layer(DefaultBodyLimit::max(
            limits::MAX_RECORD_SIZE.saturating_add(roster::limits::SIGNATURE_LEN),
        ))
        .with_state(store)
}

/// A store to serve.
#[must_use]
pub fn shared_store() -> Shared {
    Arc::new(Mutex::new(Store::new()))
}

/// Parses the key a route names.
fn parse_key(text: &str) -> Option<KeyId> {
    let bytes = roster::hex::decode(text)?;
    let fixed: [u8; 32] = bytes.try_into().ok()?;
    Some(KeyId::from_bytes(fixed))
}

/// `GET /r/{key}` — serves the record for a key, to anyone who asks.
async fn fetch(
    State(store): State<Shared>,
    Path(key): Path<String>,
) -> core::result::Result<Vec<u8>, StatusCode> {
    let key = parse_key(&key).ok_or(StatusCode::BAD_REQUEST)?;
    let held = store.lock().await;
    // The exact bytes the device signed, so the client verifies what was signed
    // rather than a re-encoding of what this service understood.
    held.get(&key).map(SignedRecord::to_bytes).ok_or(StatusCode::NOT_FOUND)
}

/// `PUT /r/{key}` — accepts a record on the evidence of its signature alone.
async fn publish(
    State(store): State<Shared>,
    Path(key): Path<String>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> core::result::Result<StatusCode, (StatusCode, String)> {
    let key =
        parse_key(&key).ok_or((StatusCode::BAD_REQUEST, "the path is not a key".to_owned()))?;

    let record = SignedRecord::decode_and_verify(&body).map_err(status_for)?;

    // The record must belong where it is being filed. Without this a device
    // could publish its own valid record under somebody else's key, and every
    // signature check would still pass.
    if record.key().key_id() != key {
        return Err(status_for(Error::SignatureInvalid));
    }

    store
        .lock()
        .await
        .publish(record, &source.ip().to_string())
        .map_err(status_for)
        .map(|()| StatusCode::NO_CONTENT)
}

/// Maps a refusal to a status a client can act on.
///
/// The distinction the specification requires survives the wire: `429` says wait
/// and try the same record again, `4xx` otherwise says do not.
fn status_for(error: Error) -> (StatusCode, String) {
    let status = match &error {
        Error::Limit(Limit::PublishRate { .. } | Limit::StorageFull { .. }) => {
            StatusCode::TOO_MANY_REQUESTS
        }
        Error::Limit(Limit::RecordSize { .. }) => StatusCode::PAYLOAD_TOO_LARGE,
        Error::Limit(Limit::AddressCount { .. } | Limit::KeysPerSource { .. }) => {
            StatusCode::FORBIDDEN
        }
        Error::SequenceNotNewer { .. } | Error::Equivocation { .. } => StatusCode::CONFLICT,
        Error::SignatureInvalid | Error::ForeignNetwork | Error::Malformed(_) => {
            StatusCode::BAD_REQUEST
        }
    };
    (status, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key in a route is a key id in hex, and nothing else parses.
    #[test]
    fn only_a_key_id_parses() {
        let key = KeyId::from_bytes([5; 32]);
        assert_eq!(parse_key(&roster::hex::encode(key.as_bytes())), Some(key));

        for bad in ["", "zz", "0011", &"aa".repeat(33)] {
            assert_eq!(parse_key(bad), None, "{bad:?} must not parse");
        }
    }

    /// A rate refusal invites a retry; a bad record does not. A client that
    /// retried a bad signature forever would be hammering the one piece of
    /// shared infrastructure the project runs.
    #[test]
    fn a_wait_and_a_refusal_are_different_statuses() {
        let (wait, _) = status_for(Error::Limit(Limit::PublishRate { interval_secs: 5 }));
        assert_eq!(wait, StatusCode::TOO_MANY_REQUESTS);

        let (refused, _) = status_for(Error::SignatureInvalid);
        assert_eq!(refused, StatusCode::BAD_REQUEST);

        let (conflict, _) = status_for(Error::SequenceNotNewer { offered: 1, held: 2 });
        assert_eq!(conflict, StatusCode::CONFLICT);
    }

    /// The reason reaches the client, not just a bare status.
    #[test]
    fn the_reason_survives_to_the_wire() {
        let (_, message) = status_for(Error::SequenceNotNewer { offered: 4, held: 9 });
        assert!(message.contains('4') && message.contains('9'), "{message}");
    }
}

//! Publishing a record, and fetching one.
//!
//! # It caches nothing and dials nothing
//!
//! §2.6b budgets 500 ms from activation to a usable session **using cached
//! endpoints, without waiting for the rendezvous**. That only holds if the cache
//! lives above this crate: a client that cached internally would make the budget
//! depend on this crate's timing, and a node could not try a known address until
//! this crate had decided it was allowed to.
//!
//! So `windows-daemon` owns the cache and the schedule. This fetches, verifies,
//! and returns addresses.
//!
//! # An address is a hint, never an authority
//!
//! What comes back says *where to try*, never *who a peer is*. Membership stays
//! the roster's, and a session opened to an address learned here is
//! authenticated exactly as one learned any other way. A record naming an
//! address where a stranger answers produces no session — the transport refuses
//! it, as it would anywhere else.

use roster::id::{KeyId, NetworkId};
use roster::sign::Signer;

use crate::error::{Error, Result};
use crate::record::{Record, SignedRecord};

/// Talks to one rendezvous.
#[derive(Debug, Clone)]
pub struct Client {
    /// The service's base URL, without a trailing slash.
    base: String,
    /// The network whose records this client will accept.
    network: NetworkId,
    /// HTTP, kept between calls so a connection can be reused.
    http: reqwest::Client,
}

/// What a fetch produced, and what the caller needs to judge the next one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The addresses the device published. Opaque strings: this crate does not
    /// parse them, because the transport decides what an address means and a
    /// rendezvous that parsed them would need changing whenever that did.
    pub addresses: Vec<String>,
    /// The sequence this record carried, for the caller to remember.
    pub sequence: u64,
}

impl Client {
    /// Points a client at a service.
    #[must_use]
    pub fn new(base: impl Into<String>, network: NetworkId) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_owned(),
            network,
            http: reqwest::Client::new(),
        }
    }

    /// Points a client at a service verified by one certificate and nothing else.
    ///
    /// For a rendezvous on the relay's host, serving the relay's certificate: the
    /// network already pins it, and this is the same trust the relay is dialled
    /// with. **The built-in roots are off**, so no public authority can vouch for
    /// a server here; a server presenting any other certificate is not spoken to.
    ///
    /// **HTTPS only**: a pinned client given an `http://` base would verify
    /// nothing at all, so it refuses one rather than quietly speaking in clear.
    ///
    /// `None` when the certificate cannot become a trust anchor. There is then
    /// no client, which the caller treats as no rendezvous — failing closed, as
    /// the network already works without one — and never as a client falling
    /// back to the public roots.
    #[must_use]
    pub fn pinned(base: impl Into<String>, network: NetworkId, certificate: &[u8]) -> Option<Self> {
        let anchor = reqwest::Certificate::from_der(certificate).ok()?;
        let http = reqwest::Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(anchor)
            .https_only(true)
            .build()
            .ok()?;
        Some(Self { base: base.into().trim_end_matches('/').to_owned(), network, http })
    }

    /// The URL a key is stored under.
    fn url(&self, key: &KeyId) -> String {
        format!("{}/r/{}", self.base, roster::hex::encode(key.as_bytes()))
    }

    /// Signs and publishes a record.
    pub async fn publish(
        &self,
        sequence: u64,
        addresses: Vec<String>,
        signer: &dyn Signer,
        key: roster::sign::PublicKey,
    ) -> Result<()> {
        let key_id = key.key_id();
        let record = Record::new(key, self.network, sequence, addresses)?;
        let signed = SignedRecord::sign(record, signer)?;

        let response = self
            .http
            .put(self.url(&key_id))
            .body(signed.to_bytes())
            .send()
            .await
            .map_err(|_| Error::Malformed(roster::Error::UnexpectedEof))?;

        if response.status().is_success() {
            return Ok(());
        }
        Err(refusal_for(response.status()))
    }

    /// Fetches and verifies the record for a key.
    ///
    /// `seen` is the highest sequence this caller has already accepted for the
    /// key, if any. A record that does not exceed it is refused — that rule,
    /// held by the client rather than the service, is what makes rolling a
    /// client back impossible even when the service is compromised or has
    /// restarted with an empty store.
    pub async fn fetch(&self, key: &KeyId, seen: Option<u64>) -> Result<Option<Fetched>> {
        let response = self
            .http
            .get(self.url(key))
            .send()
            .await
            .map_err(|_| Error::Malformed(roster::Error::UnexpectedEof))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(refusal_for(response.status()));
        }

        let body =
            response.bytes().await.map_err(|_| Error::Malformed(roster::Error::UnexpectedEof))?;
        let signed = SignedRecord::decode_and_verify(&body)?;

        // The key it claims must be the key that was asked for, or a service
        // could answer one question with another device's honest record.
        if signed.key().key_id() != *key {
            return Err(Error::SignatureInvalid);
        }
        // Opened only after the signature: a record that does not open for this
        // network is refused, and none of its addresses is ever returned.
        let record = signed.open(&self.network)?;
        if let Some(highest) = seen
            && record.sequence <= highest
        {
            return Err(Error::SequenceNotNewer { offered: record.sequence, held: highest });
        }

        Ok(Some(Fetched { addresses: record.addresses.clone(), sequence: record.sequence }))
    }
}

/// Recovers a refusal from a status.
///
/// The service's distinction between "wait" and "do not bother" has to survive
/// the wire, or a client cannot tell a rate limit from a rejected record.
fn refusal_for(status: reqwest::StatusCode) -> Error {
    match status {
        reqwest::StatusCode::TOO_MANY_REQUESTS => Error::Limit(crate::error::Limit::PublishRate {
            interval_secs: crate::limits::MIN_PUBLISH_INTERVAL_SECS,
        }),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE => Error::Limit(crate::error::Limit::RecordSize {
            len: 0,
            limit: crate::limits::MAX_RECORD_SIZE,
        }),
        reqwest::StatusCode::FORBIDDEN => Error::Limit(crate::error::Limit::KeysPerSource {
            limit: crate::limits::MAX_KEYS_PER_SOURCE,
        }),
        reqwest::StatusCode::CONFLICT => Error::SequenceNotNewer { offered: 0, held: 0 },
        _ => Error::SignatureInvalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A pinned client trusts its certificate and no public authority.**
    ///
    /// Asserted on the code because no test here can show it: telling the two
    /// apart needs a server with a publicly trusted certificate for a name the
    /// test controls, which is the internet. With the built-in roots left on,
    /// any public authority could vouch for an impostor on the relay's host.
    #[test]
    fn a_pinned_client_trusts_its_certificate_alone() {
        let source = include_str!("client.rs");
        let code = source.split("#[cfg(test)]").next().unwrap_or(source);
        let pinned = code
            .split("pub fn pinned(")
            .nth(1)
            .and_then(|rest| rest.split("\n    }\n").next())
            .unwrap_or_default();

        assert!(pinned.contains(".tls_built_in_root_certs(false)"), "no public roots: {pinned}");
        assert!(pinned.contains(".https_only(true)"), "and never in clear: {pinned}");
        assert!(!pinned.contains("unwrap_or"), "and no fallback to another client: {pinned}");
    }

    #[test]
    fn a_trailing_slash_does_not_double_up() {
        let network = NetworkId::from_bytes([1; 32]);
        let key = KeyId::from_bytes([2; 32]);
        let with = Client::new("http://example.test/", network);
        let without = Client::new("http://example.test", network);
        assert_eq!(with.url(&key), without.url(&key));
        assert!(!with.url(&key).contains("//r/"));
    }

    /// A rate limit must stay distinguishable from a rejected record after the
    /// round trip, or a client cannot tell whether waiting would help.
    #[test]
    fn the_refusal_kind_survives_the_status_code() {
        assert!(refusal_for(reqwest::StatusCode::TOO_MANY_REQUESTS).is_retryable());
        assert!(!refusal_for(reqwest::StatusCode::BAD_REQUEST).is_retryable());
        assert!(refusal_for(reqwest::StatusCode::BAD_REQUEST).is_about_the_record());
        assert!(refusal_for(reqwest::StatusCode::TOO_MANY_REQUESTS).is_about_the_publisher());
    }
}

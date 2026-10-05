//! Where a device says it can be reached.
//!
//! `transport-iroh` proved two nodes can find each other and punch through real
//! NATs — but only because both were told the same relay and the relay knew
//! where each was. This answers the question a node asks when it wakes up:
//! *where was this peer last seen, so I can try it directly before falling back
//! to anything?*
//!
//! DESIGN.md §2.6b makes that the product's main performance metric: under 500 ms
//! from activation to a usable session, **using cached endpoints, without
//! waiting for the rendezvous**. Both halves matter. The cache is what makes
//! 500 ms possible, and the cache has to be filled from somewhere.
//!
//! # What this service is allowed to be
//!
//! §6.1 states it exactly. A compromised rendezvous:
//!
//! - **cannot inject devices** — membership is the roster's, and a record is not
//!   evidence of it;
//! - **cannot alter a record** — the device signed it, and an altered one no
//!   longer verifies;
//! - **cannot produce a record that verifies** — it holds no key that any client
//!   would accept.
//!
//! It **can censor, delay, and observe**. Those are accepted, and they are the
//! reason a network must keep working when this is unreachable. §8 is blunt
//! about the consequence: failing to connect while standing half a metre from a
//! node, because a server was down, would be an absurd failure for a product
//! sold on sovereignty.
//!
//! # Signatures do everything
//!
//! §2.8: no authentication. The service has no accounts, no tokens, and no
//! notion of who is calling. It accepts a publication because the signature
//! verifies under the key it is stored under, and serves a fetch to anyone.
//!
//! There is nothing in it to steal, nothing to phish, and no credential whose
//! loss would mean anything.
//!
//! # The sequence is the only freshness rule
//!
//! A record is accepted only if its sequence exceeds the one already held — on
//! the service, and again on the client against the highest it has seen for that
//! key. That is what makes rolling a client back impossible.
//!
//! There is deliberately **no timestamp**. `DESIGN.md` §0 forbids timestamps
//! deciding validity, and both ways of adding one fail here: a device-signed
//! time is signer-chosen, so a wrong clock silently removes a device from reach;
//! a server-recorded time trusts the party §6.1 says may delay. The cost is that
//! a client which has never seen a key can be served an old record — and §2.9
//! opens the relay in parallel, so a stale hint costs one wasted probe rather
//! than a failed connection.
//!
//! # Deliberately elsewhere
//!
//! - Storing the roster here, which §4.7 contemplates — `roster-sync`. A second
//!   path into the roster would be a second thing to eclipse.
//! - Finding peers on a LAN — `local-discovery`. §8 means nothing on that path
//!   may depend on this service.
//! - Deciding when to publish, how long to cache, when to re-fetch —
//!   `windows-daemon`.
//! - Running the service: TLS, supervision, deployment. Operations.

pub mod client;
pub mod error;
pub mod limits;
pub mod record;
pub mod service;
pub mod store;

pub use client::{Client, Fetched};
pub use error::{Error, Limit, Result};
pub use record::{DOMAIN_TAG, Record, SEAL_CONTEXT, SignedRecord};
pub use store::Store;

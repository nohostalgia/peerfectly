//! Finding a peer on the same network, with no internet at all.
//!
//! Every path built before this one leaves the building. DESIGN.md §8 states
//! the requirement and the failure it exists to prevent: the network must work
//! with the internet off, and if LAN candidates came only from the rendezvous,
//! failing to connect while standing half a metre from your own node would be an
//! absurd outcome for a product sold on sovereignty.
//!
//! §2.9 makes the local network the **first** path tried, before global
//! addressing, before hole punching, before the relay.
//!
//! # Discovery proposes; the roster authorises
//!
//! §8 is explicit: anyone on a local network can announce any key. What comes
//! out of this crate is **candidate addresses**, never a device and never a
//! membership decision. A session opened to a discovered address is
//! authenticated exactly as one opened to an address learned any other way.
//!
//! # The announcement is obfuscated, and that is all
//!
//! Packets are encrypted under a key derived from the network id, so a stranger
//! on the same wifi sees random-looking bytes rather than a public key and a
//! presence beacon.
//!
//! **This is obfuscation, not confidentiality.** The network id is not a secret:
//! every member knows it, and so does every *former* member whose device was
//! revoked. It defends against an observer who never held the roster and against
//! nobody else. Successful decryption is never authentication.
//!
//! # The medium is assumed to fail
//!
//! §8 warns that multicast on wireless networks is filtered outright or carried
//! at the lowest bitrate. So announcements repeat, and the **last known local
//! addresses are tried before anything is heard**. A design that waited for an
//! announcement would be slowest exactly where §2.6b's 500 ms budget is
//! measured.
//!
//! # Deliberately elsewhere
//!
//! - When to announce, how often, and on which interfaces — `windows-daemon`.
//! - Gathering the reflexive addresses that reveal two peers share one external
//!   address; the ordering takes them as a parameter rather than reaching into
//!   the transport.
//! - Membership, roles, authority. The roster's, entirely.

pub mod announce;
pub mod cache;
pub mod error;
pub mod limits;
pub mod multicast;
pub mod order;

pub use announce::{Announcement, DOMAIN_TAG};
pub use cache::Cache;
pub use error::{Error, Result};
pub use multicast::Multicast;
pub use order::{Candidate, Conditions, Source, order};

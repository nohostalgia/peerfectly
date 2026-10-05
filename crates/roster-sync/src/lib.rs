//! How two nodes reconcile their rosters over an authenticated session.
//!
//! DESIGN.md §4.7 is the whole distribution model, and it is one paragraph: no
//! privileged channel; whenever two nodes connect they exchange the ids of the
//! operations they know and pass over the missing ones. A node switched off for
//! a month catches up on its first connection with anyone, and revocations
//! spread by contagion.
//!
//! Contagion is what makes the central property hold. A revocation is worth
//! nothing while it sits on the admin's phone.
//!
//! # What this crate decides, and what it does not
//!
//! It decides **which bytes are sent** and **how many are accepted from a given
//! peer**. It decides nothing about whether an operation is valid, who is a
//! member, or what the derived state is — every operation and snapshot received
//! goes through [`roster::roster::Roster`], which is the only authority. A sync
//! layer that decided any of that would be a second authority, consulted far
//! more often than the signed log and disagreeing with it under exactly the
//! conditions that matter.
//!
//! # Two policies worth stating up front
//!
//! **Refuse at the door, never evict.** A peer over its share of the pending set
//! has its next operation refused; nothing already pending is displaced. A
//! refused operation stays with its sender, which offers it again — the refusal
//! is recoverable. An evicted one is gone from a node that already reported
//! accepting it, and the entry displaced might have been the revocation.
//!
//! **Throttle, never disconnect.** A refusal costs the sender a quota slot and
//! nothing else. A node that punished a peer for the *content* it relays could
//! be aimed: an attacker forges one operation, has an honest node relay it, and
//! honest nodes drop each other — one operation, no key, and a node is removed
//! from everyone's view. Membership is the only ground on which a session ends,
//! and that decision already belongs to the transport, derived from the signed
//! log.
//!
//! # Deliberately elsewhere
//!
//! - Dialling, addressing, NAT and relays — the transport. This crate is handed
//!   sessions.
//! - The relay path that lets two nodes meet at all — `rendezvous-service`.
//! - Multicast announcement on a LAN — `local-discovery`.
//! - Detecting that an author equivocated across peers —
//!   `equivocation-detection`. This crate must preserve that evidence, not act
//!   on it: refusals are reported rather than swallowed.
//! - The loop, the schedule and the concurrency shape — `windows-daemon`.

pub mod error;
pub mod limits;
pub mod message;
pub mod quota;
pub mod syncer;

pub use error::{Error, Result};
pub use syncer::{Held, Reception, Refusal, Syncer};

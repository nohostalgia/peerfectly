//! How a device that belongs to no network becomes a member of one.
//!
//! Every other crate here assumes a roster already exists. This one is about the
//! moment before that, when a device has keys and nothing else, and the question
//! is how it can be given a network without anybody having to trust the way the
//! bytes travelled.
//!
//! # The admin opens the door, and the device waits behind it
//!
//! A device with no network is unreachable in both directions: it registers at
//! no relay, so nobody can dial it, and it cannot announce on the local network
//! either, because announcements are sealed with a network identifier it does
//! not have. Something has to break that symmetry.
//!
//! An admin issues an **invite**: the network's relay, its id, and a secret.
//! The device derives a rendezvous key from the secret, registers under it at
//! that relay, and waits; the admin that issued the invite derives the same key
//! and dials it. The admin's side never listens.
//!
//! # What the invite's secret is, and is not
//!
//! The secret only says where to meet. Whoever learns it can reach the waiting
//! device first, so nothing about an enrolment's safety rests on it staying
//! secret. What makes an enrolment safe is three checks that do not depend on
//! it:
//!
//! - **No confirmation code.** Enrolment is asynchronous: a request is kept
//!   until a person approves it, and nobody compares two screens. A six-digit
//!   code was a second bearer secret when sent the way the invite was, and the
//!   responder of the channel's handshake could grind its ephemeral to match it.
//! - **The device's keys are proved.** The channel of an invite authenticates
//!   only the rendezvous key. The transport key is proved by a signature over
//!   the channel's material; the signing key, from which a device's identity
//!   comes, by a signature over the join's request — the invite answered and the
//!   other two keys — made once, when the person runs the join. Without these,
//!   an introduction could pair one device's identity with another's transport
//!   key, and a roster keeps the first admission of a device id for ever.
//! - **The delivered roster is verified, not trusted.** Who handed it over does
//!   not matter. It must admit this device's own keys, be signed by an admin,
//!   derive consistently, and be of the network the invite names.
//!
//! # What a person still has to do
//!
//! Compare six digits on two screens. §6.2 lists a person not checking as an
//! accepted limit of this design, and it stays one: this narrows it by making one
//! side *type* what the other displays, so a mismatch is caught by somebody
//! looking rather than by somebody agreeing.
//!
//! # Deliberately elsewhere
//!
//! - Sockets, waiting, deadlines and the command line — `windows-daemon`. This
//!   crate is a format and a set of rules about bytes, so it can be tested
//!   without a network and reused by a phone.
//! - The enrolment endpoint and the channel material it exports —
//!   `transport-convesso`.
//! - Membership, roles and authority — the roster's, entirely. An admin decides
//!   what a joining device is permitted to be; the device only proposes a name.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
pub mod adopt;
pub mod error;
pub mod exchange;
pub mod invite;
pub mod limits;

#[cfg(feature = "std")]
pub use adopt::Adopted;
pub use error::{Error, Result};
pub use exchange::{DOMAIN_POSSESSION, DOMAIN_REQUEST, Possession, request_material};
pub use invite::Invite;

//! How a device that belongs to no network becomes a member of one.
//!
//! Every other crate here assumes a roster already exists. This one is about the
//! moment before that, when a device has keys and nothing else, and the question
//! is how it can be given a network without anybody having to trust the way the
//! bytes travelled.
//!
//! # The device that is joining goes first
//!
//! A device with no network is unreachable in both directions: it registers at
//! no relay, so nobody can dial it, and it cannot announce on the local network
//! either, because announcements are sealed with a network identifier it does
//! not have. Something has to break that symmetry.
//!
//! A person types a relay address. That is enough to make the device reachable —
//! an endpoint registers at a relay by its own key and knows nothing about any
//! roster — and it is the smallest thing anybody can carry between two machines
//! that are not on the same network. The device then shows what it is, and the
//! admin comes to it.
//!
//! The direction follows from what is known rather than from preference: dialling
//! needs the peer's transport key, which is thirty-two bytes nobody types, and
//! the joining payload is what carries it.
//!
//! # Nothing here is secret, and nothing here is authority
//!
//! The joining payload is **public**. It is on a screen, it will be photographed,
//! and it will be pasted into a chat. Nothing in this crate depends on it being
//! secret, and holding one grants nothing: it says who is asking, and asking is
//! free.
//!
//! What makes an enrolment safe is not the privacy of the payload but three
//! checks that do not depend on it:
//!
//! - **The confirmation code is bound to the channel.** Every key involved is
//!   public, so a code derived from keys alone could be computed in advance by
//!   anyone who had seen the payload — and then matched by grinding key pairs
//!   against a six-digit space. Binding it to material exported from the
//!   established channel means the value being matched does not exist until the
//!   channel does.
//! - **Both keys are proved.** The channel authenticates the transport key. The
//!   signing key — which is where a device's identity comes from — is proved by
//!   a signature over that same channel material. Without it, a payload could
//!   pair one device's identity with another's transport key, and a roster keeps
//!   the first admission of a device id for ever.
//! - **The delivered roster is verified, not trusted.** Who handed it over does
//!   not matter. It must admit this device's own keys, be signed by an admin, and
//!   derive consistently — and where this device accepted a relay certificate
//!   nothing had vouched for, the network must pin that same certificate.
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
//!   `transport-iroh`.
//! - Membership, roles and authority — the roster's, entirely. An admin decides
//!   what a joining device is permitted to be; the payload only proposes a name.

pub mod adopt;
pub mod code;
pub mod error;
pub mod exchange;
pub mod limits;
pub mod payload;

pub use adopt::Adopted;
pub use code::{Confirmation, DOMAIN_CODE};
pub use error::{Error, Result};
pub use exchange::{DOMAIN_POSSESSION, Possession};
pub use payload::Joining;

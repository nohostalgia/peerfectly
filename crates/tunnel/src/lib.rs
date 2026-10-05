//! Addresses on the overlay, and the rule that a packet's source must match its
//! session.
//!
//! Nine changes built a network that can find a peer anywhere, authenticate it
//! against a signed roster, and carry bytes to it. This turns that into
//! something a person's own `ssh` and `curl` can address.
//!
//! # What the source rule is actually for
//!
//! DESIGN.md §2.5: *routing becomes authentication — a packet whose source
//! does not match the hash of the key of the session it arrived on is
//! dropped.*
//!
//! That reads like a defence against outsiders, and it is not. The transport
//! already refuses a peer the roster does not name before a packet flows. The
//! rule is aimed at a **member spoofing another member's source address inside
//! its own legitimate session** — claiming to be someone else to a service on
//! the far side. Without it, membership buys an attacker the ability to
//! impersonate every other member at the IP layer, and every access rule written
//! in terms of addresses becomes decoration.
//!
//! # Split routing is enforced here, not configured
//!
//! §2.6 requires the tunnel to carry only the network's prefix and never a
//! default route: a VPN that captures everything drains the battery, breaks
//! streaming, and gets switched off — and a tunnel a person switched off
//! protects nothing. Checking the destination in code means a misconfigured
//! routing table cannot quietly turn this into a full tunnel.
//!
//! # This layer decides nothing the roster decides
//!
//! A packet is accepted because it arrived on an authenticated session and its
//! source matches that session. That is a statement about the packet, never
//! about the peer's standing — which the roster has settled and may settle
//! differently a moment later. There is no membership list here and nothing is
//! cached.
//!
//! # Deliberately elsewhere
//!
//! - Creating a real TUN device, installing routes, serving the resolver —
//!   `windows-daemon`, and the same through `VpnService` in `android-client`.
//! - Deciding when the tunnel is up. §2.6b makes that a person's deliberate act.
//! - Resolving names. The suffix is a roster parameter this crate reads and does
//!   not serve.

pub mod address;
pub mod device;
pub mod holdings;
pub mod limits;
pub mod memory;
pub mod outcome;

pub use address::{Prefix, address_of, ipv4_candidate};
pub use device::{Packets, Tunnel, destination_of};
pub use holdings::{Collision, Ipv4Holdings};
pub use memory::MemoryDevice;
pub use outcome::{Error, Inbound, Outbound, Result};

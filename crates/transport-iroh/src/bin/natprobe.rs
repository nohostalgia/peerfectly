//! Measures how often a connection goes direct rather than through the relay.
//!
//! The instrument the NAT matrix and the real-world measurement both use. It
//! answers one question — *what fraction of connections traverse NAT?* — because
//! that is the question DESIGN.md §10.4 gates the architecture on, and a tool
//! that answered more would be harder to trust about the one thing that matters.
//!
//! Both ends derive the same two-device network from seeds, so no roster has to
//! be shipped between machines and both sides agree on membership without any
//! coordination. The keys are deterministic: this is a test instrument, and the
//! seeds are on the command line.
//!
//! ```text
//! # the side that waits, started first
//! natprobe --role accept --self 1 --peer 2 --relay https://relay:443 --repeat 20
//!
//! # the side that dials
//! natprobe --role dial --self 2 --peer 1 --relay https://relay:443 --repeat 20 \
//!          --label "TIM mobile, tethered"
//! ```
//!
//! A relay you run yourself presents a certificate no public authority signed,
//! so `--relay-cert relay.pem` is needed to reach it at all. Without it the
//! handshake fails, no endpoint registers a home relay, and every attempt times
//! out — which reads as a NAT finding and is not one.
//!
//! Each attempt prints one JSON object, and a final summary object carries the
//! percentage. A percentage without its conditions is not a finding, so the
//! summary also records what the machine can determine about its own network,
//! and `--label` carries what it cannot.
//!
//! # Every attempt rebinds
//!
//! A fresh endpoint, and so a fresh UDP socket and a fresh NAT mapping, for each
//! attempt. Reusing one socket would make every attempt after the first
//! artificially easy — the mapping is already open and the peer already known —
//! and the number would describe a warm path rather than the cold connection a
//! user actually makes.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "reporting a measurement is this binary's entire purpose"
)]

use std::net::{IpAddr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use identity::{NodeIdentity, PrivateKey};
use roster::id::NetworkId;
use roster::roster::Roster;
use roster::sign::sign_operation;
use roster::state::RosterState;
use roster::types::{Algorithm, NetworkParams, OperationBody, OperationCore, Role};
use transport::session::Transport;
use transport_iroh::IrohTransport;

/// Whether the address diagnostics have been printed yet.
static REPORTED_ADDRESSES: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// How long to wait for a session before calling an attempt a failure.
const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to watch for the path to become direct, by default.
///
/// A session is usable over the relay immediately and migrates when hole
/// punching succeeds, so the measurement is taken *after* a pause. Reporting the
/// path at the instant of connection would record "relayed" for every connection
/// that was about to go direct.
const SETTLE_DEFAULT_SECS: u64 = 15;

/// A deterministic device identity from a seed.
fn identity_for(seed: u8) -> NodeIdentity {
    let signing = PrivateKey::from_material(Algorithm::Ed25519, [seed; 32]).expect("valid");
    let transport = PrivateKey::from_material(Algorithm::Ed25519, [seed.wrapping_add(0x80); 32])
        .expect("valid");
    let attestation = PrivateKey::from_material(Algorithm::Ed25519, [seed.wrapping_add(0x40); 32])
        .expect("valid");
    NodeIdentity::assemble(signing, transport, attestation).expect("assembles")
}

/// The relay's certificate, as PEM or as DER.
///
/// Checked here rather than pinned blindly: a pin that is not a certificate
/// fails at bind, and a probe that could not tell that apart from a network
/// failure would report a NAT result it never measured.
fn certificate_at(path: &str) -> Result<Vec<u8>, String> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject as _;

    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";

    let bytes = std::fs::read(path).map_err(|cause| format!("{path}: {cause}"))?;
    if bytes.windows(BEGIN.len()).any(|window| window == BEGIN) {
        return CertificateDer::from_pem_slice(&bytes)
            .map(|certificate| certificate.to_vec())
            .map_err(|cause| format!("{path}: not a usable PEM certificate: {cause}"));
    }
    // DER: an ASN.1 SEQUENCE begins 0x30.
    if bytes.first() != Some(&0x30) {
        return Err(format!("{path}: neither a PEM certificate nor DER"));
    }
    Ok(bytes)
}

/// The two-device network both ends derive, identically.
fn network(
    founder: &NodeIdentity,
    joiner: &NodeIdentity,
    relay: Option<&str>,
    certificate: Option<Vec<u8>>,
) -> RosterState {
    let params = NetworkParams::with_relay(
        vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
        relay,
        "probe.internal",
        2_592_000,
    )
    .expect("valid parameters");
    let params = match certificate {
        Some(certificate) => params.pinning(certificate).expect("a usable certificate"),
        None => params,
    };

    let genesis = OperationCore::new(
        1,
        Algorithm::Ed25519,
        OperationBody::CreateNetwork {
            device: founder.device_spec("a", Role::Admin, true, vec![]).expect("spec"),
            params,
        },
        vec![],
        founder.signing_key().key_id(),
        NetworkId::from_bytes([0; 32]),
    )
    .expect("well-formed");
    let genesis_bytes = sign_operation(&genesis, founder.signer()).expect("signs");
    let id = NetworkId::from_bytes(*genesis.id().as_bytes());

    let add = OperationCore::new(
        2,
        Algorithm::Ed25519,
        OperationBody::AddDevice(
            joiner.device_spec("b", Role::Member, false, vec![]).expect("spec"),
        ),
        vec![genesis.id()],
        founder.signing_key().key_id(),
        id,
    )
    .expect("well-formed");
    let add_bytes = sign_operation(&add, founder.signer()).expect("signs");

    let mut roster = Roster::new();
    assert!(roster.offer_bytes(&genesis_bytes).is_accepted(), "genesis");
    assert!(roster.offer_bytes(&add_bytes).is_accepted(), "add");
    roster.state().expect("derives")
}

/// Reads `--name value` pairs.
fn argument(name: &str) -> Option<String> {
    let mut args = std::env::args();
    while let Some(arg) = args.next() {
        if arg == name {
            return args.next();
        }
    }
    None
}

/// What one connection attempt produced.
struct Attempt {
    /// Whether a session was established at all.
    established: bool,
    /// Whether it ended up on a direct path rather than the relay.
    direct: bool,
    /// Whether it actually carried bytes, rather than merely handshaking.
    carried: bool,
    /// Milliseconds from starting the attempt to holding a session.
    ms: u128,
}

/// The address this machine routes from, and whether it has IPv6 at all.
///
/// `connect` on a UDP socket sends nothing; it only makes the kernel choose a
/// route. So this finds the outbound interface without touching the network, and
/// finds the absence of IPv6 without waiting for anything to time out. The
/// addresses used are the documentation ranges, which nothing routes to.
fn local_conditions() -> (Option<IpAddr>, bool) {
    let v4 = UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect("192.0.2.1:53")?;
            socket.local_addr()
        })
        .map(|addr| addr.ip())
        .ok();

    let v6 = UdpSocket::bind("[::]:0")
        .and_then(|socket| {
            socket.connect("[2001:db8::1]:53")?;
            socket.local_addr()
        })
        .is_ok();

    (v4, v6)
}

/// Whether an address is inside the range carriers use for CGNAT.
///
/// A machine holding one of these is behind carrier-grade NAT itself, which §2.9
/// says is common on Italian mobile and fixed-wireless networks. A machine on
/// `192.168.x` may *still* be behind CGNAT one hop further out — this catches
/// the obvious case, not every case, and the label is where the rest goes.
fn is_cgnat(address: Option<IpAddr>) -> bool {
    match address {
        Some(IpAddr::V4(v4)) => {
            let [a, b, ..] = v4.octets();
            a == 100 && (64..=127).contains(&b)
        }
        _ => false,
    }
}

/// Runs one attempt on a freshly bound endpoint.
async fn one_attempt(
    role: &str,
    own: &NodeIdentity,
    peer: &NodeIdentity,
    state: RosterState,
    relay: Option<&str>,
    settle: Duration,
) -> Attempt {
    let failed = Attempt { established: false, direct: false, carried: false, ms: 0 };

    // The matrix and a self-signed relay need this; a relay with a real
    // certificate does not, and a build without the feature cannot reach it.
    #[cfg(feature = "insecure-test-relay")]
    let bound = IrohTransport::bind_trusting_any_relay_certificate(own, state).await;
    #[cfg(not(feature = "insecure-test-relay"))]
    let bound = IrohTransport::bind(own, state).await;

    let Ok(transport) = bound else {
        return failed;
    };

    // Snapshot before the relay is contacted, so what discovery adds can be
    // named exactly rather than guessed at. A host with several interfaces —
    // a virtual adapter, a container bridge — has many local addresses, and
    // "an address that is not my outbound one" wrongly counts those as learned.
    let before = transport.observed_addresses();

    if relay.is_some() {
        let _ = tokio::time::timeout(ESTABLISH_TIMEOUT, transport.endpoint().online()).await;
    }

    // Reported once, because it is the fact that distinguishes "these networks
    // do not traverse" from "this node never learned where it is". Only the
    // first tells you anything about the architecture.
    if !REPORTED_ADDRESSES.swap(true, core::sync::atomic::Ordering::Relaxed) {
        let after = transport.observed_addresses();
        let learned: Vec<&String> = after.iter().filter(|addr| !before.contains(addr)).collect();
        eprintln!("  addresses before the relay: {before:?}");
        eprintln!("  learned from the relay:     {learned:?}");
        // Two separate facts. Conflating them is what voided the first
        // measurement: discovery can be working perfectly and still return only
        // private addresses, behind carrier-grade NAT or inside a lab.
        eprintln!(
            "  address discovery:  {}",
            if learned.iter().any(|addr| addr.starts_with("ip:")) {
                "working (the relay reported an address this host did not know)"
            } else {
                "NOT WORKING — the relay reported no address for this host"
            }
        );
        eprintln!(
            "  routable address:   {}",
            if transport.knows_a_public_address() {
                "yes"
            } else {
                "no (private or carrier-grade only — a peer cannot reach this directly)"
            }
        );
    }

    let started = Instant::now();
    let established = if role == "accept" {
        tokio::time::timeout(ESTABLISH_TIMEOUT, transport.accept()).await
    } else {
        let key = peer.transport_key().public_key();
        tokio::time::timeout(ESTABLISH_TIMEOUT, transport.connect(&key)).await
    };

    let Ok(Ok(session)) = established else {
        return failed;
    };
    let ms = started.elapsed().as_millis();

    // Carried, not merely handshaked: a session that cannot move a byte is not
    // a connection anyone can use.
    let carried = session.send(b"probe").await.is_ok();

    // Then wait, keeping the session busy. A path carrying nothing gives the
    // connectivity layer nothing to migrate.
    let deadline = Instant::now().checked_add(settle).unwrap_or_else(Instant::now);
    let mut direct = false;
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let _ = session.send(b"keepalive").await;
        if transport.path_to(&session.peer()).await == Some(transport::session::Path::Direct) {
            direct = true;
            break;
        }
    }

    let _ = session.close().await;
    Attempt { established: true, direct, carried, ms }
}

/// The middle value, for a spread one slow attempt cannot move.
fn median(values: &mut [u128]) -> u128 {
    values.sort_unstable();
    values.get(values.len().saturating_div(2)).copied().unwrap_or(0)
}

#[tokio::main]
async fn main() -> ExitCode {
    let role = argument("--role").unwrap_or_else(|| "dial".to_owned());
    let own_seed: u8 = argument("--self").and_then(|v| v.parse().ok()).unwrap_or(1);
    let peer_seed: u8 = argument("--peer").and_then(|v| v.parse().ok()).unwrap_or(2);
    let relay = argument("--relay");
    let repeat: usize = argument("--repeat").and_then(|v| v.parse().ok()).unwrap_or(1);
    let gap = Duration::from_secs(argument("--gap").and_then(|v| v.parse().ok()).unwrap_or(3));
    let settle = Duration::from_secs(
        argument("--settle").and_then(|v| v.parse().ok()).unwrap_or(SETTLE_DEFAULT_SECS),
    );
    let label = argument("--label").unwrap_or_else(|| "unlabelled".to_owned());
    let certificate = match argument("--relay-cert") {
        Some(path) => match certificate_at(&path) {
            Ok(certificate) => Some(certificate),
            Err(refusal) => {
                eprintln!("{refusal}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    // Seed 1 is always the founder, so both ends build the same history.
    let (founder_seed, joiner_seed) =
        if own_seed < peer_seed { (own_seed, peer_seed) } else { (peer_seed, own_seed) };
    let state = network(
        &identity_for(founder_seed),
        &identity_for(joiner_seed),
        relay.as_deref(),
        certificate,
    );

    let own = identity_for(own_seed);
    let peer = identity_for(peer_seed);

    let (local, has_v6) = local_conditions();
    let cgnat = is_cgnat(local);
    let address = local.map_or_else(|| "unknown".to_owned(), |ip| ip.to_string());

    eprintln!(
        "measuring: {repeat} attempts, role={role}, settle={}s, label={label:?}",
        settle.as_secs()
    );
    eprintln!(
        "local address {address}, IPv6 {}, obvious CGNAT {}",
        if has_v6 { "available" } else { "absent" },
        if cgnat { "yes" } else { "no" }
    );

    let mut established = 0usize;
    let mut direct = 0usize;
    let mut carried = 0usize;
    let mut timings: Vec<u128> = Vec::new();

    for attempt in 1..=repeat {
        let outcome =
            one_attempt(&role, &own, &peer, state.clone(), relay.as_deref(), settle).await;

        if outcome.established {
            established = established.saturating_add(1);
            timings.push(outcome.ms);
            if outcome.direct {
                direct = direct.saturating_add(1);
            }
            if outcome.carried {
                carried = carried.saturating_add(1);
            }
        }

        println!(
            "{{\"attempt\":{attempt},\"established\":{},\"direct\":{},\"carried\":{},\"ms\":{}}}",
            outcome.established, outcome.direct, outcome.carried, outcome.ms
        );

        if attempt < repeat {
            // A pause between attempts, so the previous mapping has expired and
            // each attempt is a cold connection rather than a continuation.
            tokio::time::sleep(gap).await;
        }
    }

    let percent = direct.saturating_mul(100).checked_div(established).unwrap_or(0);
    let relayed = established.saturating_sub(direct);
    let fastest = timings.iter().copied().min().unwrap_or(0);
    let slowest = timings.iter().copied().max().unwrap_or(0);
    let middle = median(&mut timings);

    println!(
        "{{\"summary\":true,\"label\":\"{label}\",\"role\":\"{role}\",\
         \"attempts\":{repeat},\"established\":{established},\"carried\":{carried},\
         \"direct\":{direct},\"relayed\":{relayed},\"direct_percent\":{percent},\
         \"ms_min\":{fastest},\"ms_median\":{middle},\"ms_max\":{slowest},\
         \"ipv6\":{has_v6},\"cgnat_local\":{cgnat},\"local_address\":\"{address}\"}}"
    );

    eprintln!();
    eprintln!("=== {label} ({role}) ===");
    eprintln!("  established      {established}/{repeat}");
    eprintln!("  carried bytes    {carried}/{established}");
    eprintln!("  DIRECT           {direct}/{established}  ({percent}%)");
    eprintln!("  relayed          {relayed}/{established}");
    eprintln!("  time to session  min {fastest}ms  median {middle}ms  max {slowest}ms");
    eprintln!();
    eprintln!("Record this with the carrier and access type. What the number means is");
    eprintln!("in nat-matrix/MEASUREMENT.md — a low direct percentage is a finding");
    eprintln!("about the architecture, not a bug to work around.");

    if established == 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

//! Generates the shared test-vector corpus.
//!
//! Run deliberately, never on build:
//!
//! ```text
//! cargo run -p roster --bin gen-vectors
//! ```
//!
//! The corpus is committed, and regenerating it must produce a visible diff. A
//! corpus rebuilt automatically as part of the build would bless whatever the
//! implementation currently does, which is the exact opposite of its purpose:
//! it exists to catch the day this implementation changes its mind about which
//! bytes are valid.
//!
//! Output is JSON with every byte string in hex, so a person diagnosing a
//! cross-client divergence at an unreasonable hour can read it, and so a
//! divergence in the CBOR layer cannot also break the harness meant to
//! diagnose it.
//!
//! Negative vectors are built from hand-written bytes rather than by asking the
//! encoder for them. An encoder cannot be trusted to produce the inputs that
//! prove it rejects things.

#![allow(
    clippy::panic,
    reason = "a corpus generator must abort loudly rather than emit a wrong vector"
)]

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use roster::dag::Dag;
use roster::error::Error;
use roster::hex;
use roster::id::{DeviceId, NetworkId, OperationId};
use roster::roster::{Admission, Roster};
use roster::sign::{
    Ed25519Signer, P256Signer, Signer, assemble_operation, assemble_operation_with_id,
    sign_operation, signing_input,
};
use roster::snapshot::{Snapshot, assemble_snapshot, sign_snapshot};
use roster::state::{derive, derive_with_verdicts};
use roster::types::{
    Algorithm, Capability, DeviceSpec, Ipv4Range, KeyEntry, KeyPurpose, NetworkParams,
    OperationBody, OperationCore, OperationType, Role,
};

/// A positive vector: bytes that must be accepted, with what they must produce.
struct Positive {
    /// What this vector demonstrates.
    name: String,
    /// The operation type carried.
    operation_type: &'static str,
    /// The signature algorithm.
    algorithm: &'static str,
    /// The whole operation, hex.
    operation: String,
    /// The signed core bytes, hex.
    core: String,
    /// The expected operation id, hex.
    id: String,
    /// The public key that must verify it, hex.
    public_key: String,
    /// The domain-separated bytes the signature covers, hex.
    signing_input: String,
}

/// A merge vector: an operation set, and the roster it must derive.
///
/// The whole point is the `permutations` field. A vector applied in one order
/// tests derivation; applied in several, it tests the property that derivation
/// does not depend on order, which is the one this capability turns on.
struct Merge {
    /// What this vector demonstrates.
    name: String,
    /// Which rule it pins.
    rule: &'static str,
    /// The operations, hex, in creation order.
    operations: Vec<String>,
    /// Hex of the canonical derived state, when the set derives.
    state: Option<String>,
    /// Hex of the state fingerprint, when the set derives.
    fingerprint: Option<String>,
    /// The expected failure kind, when the set does not derive.
    error_kind: Option<&'static str>,
    /// Operations that must be disregarded, and why: hex id and reason kind.
    ///
    /// These are operations a conforming node *holds*, and gives no effect to.
    invalid: Vec<(String, &'static str)>,
    /// Operations a conforming node must refuse **at admission**, and why.
    ///
    /// Distinct from `invalid` because the outcome is distinct: an operation here
    /// never enters the graph at all, so it occupies nothing and is not present
    /// to be disregarded. An implementation that admits one of these and then
    /// disregards it derives the same state and is still wrong: the graph is
    /// bounded, and a slot spent on an operation that can never have effect is a
    /// slot a revocation will need.
    refused: Vec<(String, &'static str)>,
}

/// A snapshot vector: an artifact, the operations behind it, and its verdict.
struct SnapshotVector {
    /// What this vector demonstrates.
    name: String,
    /// The snapshot artifact, hex.
    snapshot: String,
    /// The operations a node must hold to judge it, hex, in creation order.
    operations: Vec<String>,
    /// Whether it must be accepted.
    accepted: bool,
    /// The expected refusal kind, when it must not be.
    error_kind: Option<&'static str>,
    /// A second snapshot offered after the first, for the sequence vectors.
    follow_up: Option<String>,
    /// The verdict the follow-up must receive.
    follow_up_error: Option<&'static str>,
}

/// A negative vector: bytes that must be rejected, and why.
struct Negative {
    /// What this vector demonstrates.
    name: String,
    /// Where the rejection must happen.
    stage: &'static str,
    /// The whole operation, hex.
    operation: String,
    /// The expected [`Error::kind`].
    error_kind: &'static str,
    /// The key to verify against, hex, for verify-stage vectors.
    public_key: Option<String>,
    /// That key's algorithm, for verify-stage vectors.
    public_key_alg: Option<&'static str>,
}

fn main() {
    let positives = build_positives();
    let negatives = build_negatives();
    let merges = build_merges();
    let snapshots = build_snapshots();

    // Coverage is checked across both corpora together. Parse and signature
    // rejections live in the negative corpus; rejections that only exist once
    // operations are assembled into a history live in the merge corpus.
    let mut covered: std::collections::BTreeSet<&str> =
        negatives.iter().map(|vector| vector.error_kind).collect();
    for merge in &merges {
        if let Some(kind) = merge.error_kind {
            covered.insert(kind);
        }
        for (_, reason) in &merge.invalid {
            covered.insert(reason);
        }
        for (_, reason) in &merge.refused {
            covered.insert(reason);
        }
    }
    for snapshot in &snapshots {
        if let Some(kind) = snapshot.error_kind {
            covered.insert(kind);
        }
        if let Some(kind) = snapshot.follow_up_error {
            covered.insert(kind);
        }
    }
    for kind in Error::ALL_KINDS {
        if UNCOVERABLE_KINDS.contains(kind) {
            continue;
        }
        assert!(covered.contains(kind), "no vector covers `{kind}`");
    }

    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors");
    fs::create_dir_all(&directory).expect("the vectors directory can be created");

    fs::write(directory.join("positive.json"), render_positive(&positives))
        .expect("positive vectors are written");
    fs::write(directory.join("negative.json"), render_negative(&negatives))
        .expect("negative vectors are written");
    fs::write(directory.join("merge.json"), render_merge(&merges))
        .expect("merge vectors are written");
    fs::write(directory.join("snapshot.json"), render_snapshots(&snapshots))
        .expect("snapshot vectors are written");

    println!(
        "wrote {} positive, {} negative, {} merge and {} snapshot vectors covering {} reasons",
        positives.len(),
        negatives.len(),
        merges.len(),
        snapshots.len(),
        covered.len()
    );
}

/// Rejection reasons deliberately absent from the shared corpus.
///
/// Both are excluded for a reason, not for convenience:
///
/// * `stale_operation` is a *local* admission policy. Two conforming
///   implementations may configure it differently and both be right, so
///   pinning it in a corpus every client must satisfy would be wrong.
/// * `cyclic_history` cannot be constructed. An operation id covers its parent
///   list, so two operations naming each other would each need the other hash
///   first. The code detects it so that hostile input terminates; there is no
///   input to put in a vector.
const UNCOVERABLE_KINDS: &[&str] = &[
    "stale_operation",
    "cyclic_history",
    // Compaction is refused on node-local grounds — what else is held, and how
    // far behind the local frontier the region sits. Two conforming
    // implementations may differ and both be right, so pinning it in a shared
    // corpus would be wrong. `snapshots.rs` covers every gate directly.
    "compaction_refused",
];

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// The fixture network id.
fn network() -> NetworkId {
    NetworkId::from_bytes([0x11; 32])
}

/// A deterministic ed25519 signer.
fn ed25519(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed([seed; 32])
}

/// A deterministic P-256 signer.
fn p256(seed: u8) -> P256Signer {
    let mut scalar = [0x11; 32];
    if let Some(first) = scalar.first_mut() {
        *first = seed;
    }
    P256Signer::from_scalar(scalar).expect("fixture scalar is inside the curve order")
}

/// A device with a signing key and a distinct transport key.
fn device(seed: u8, name: &str, role: Role, founder: bool) -> DeviceSpec {
    let signing = KeyEntry::new(
        Algorithm::Ed25519,
        KeyPurpose::Signing,
        ed25519(seed).public_key().as_bytes().to_vec(),
    )
    .expect("well-formed");
    let transport = KeyEntry::new(
        Algorithm::Ed25519,
        KeyPurpose::Transport,
        ed25519(seed.wrapping_add(100)).public_key().as_bytes().to_vec(),
    )
    .expect("well-formed");
    let attestation = KeyEntry::new(
        Algorithm::Ed25519,
        KeyPurpose::Attestation,
        ed25519(seed.wrapping_add(200)).public_key().as_bytes().to_vec(),
    )
    .expect("well-formed");
    DeviceSpec::new(
        sorted(vec![signing, transport, attestation]),
        name,
        role,
        founder,
        vec![Capability::new("serves").expect("short")],
    )
    .expect("well-formed device")
}

/// Sorts key entries the way a device record requires.
fn sorted(mut keys: Vec<KeyEntry>) -> Vec<KeyEntry> {
    // The roster's own definition of the order, not an approximation of it.
    keys.sort_by_key(KeyEntry::order_key);
    keys
}

/// Fixture network parameters.
fn params() -> NetworkParams {
    NetworkParams::new(
        vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        "example.internal",
        2_592_000,
    )
    .expect("well-formed")
}

/// A well-formed body of each type.
fn body_of(op_type: OperationType) -> OperationBody {
    let target = device(2, "laptop", Role::Member, false)
        .device_id()
        .expect("the fixture device has a signing key");
    match op_type {
        OperationType::CreateNetwork => OperationBody::CreateNetwork {
            device: device(1, "phone", Role::Admin, true),
            params: params(),
        },
        OperationType::AddDevice => {
            OperationBody::AddDevice(device(2, "laptop", Role::Member, false))
        }
        OperationType::RevokeDevice => {
            OperationBody::RevokeDevice { device: target, reason: "lost on a train".to_owned() }
        }
        OperationType::Promote => OperationBody::Promote { device: target, founder: false },
        OperationType::Demote => OperationBody::Demote { device: target },
        OperationType::Rename => {
            OperationBody::Rename { device: target, name: "workstation".to_owned() }
        }
        OperationType::SetNetwork => OperationBody::SetNetwork(params()),
    }
}

/// A core of the given type, authored by the given signer.
fn core_for(op_type: OperationType, signer: &dyn Signer) -> OperationCore {
    OperationCore::new(
        1_735_689_600_000,
        signer.algorithm(),
        body_of(op_type),
        vec![OperationId::from_bytes([0xaa; 32])],
        signer.key_id(),
        network(),
    )
    .expect("well-formed core")
}

// ---------------------------------------------------------------------------
// Positive vectors
// ---------------------------------------------------------------------------

/// One vector per operation type per algorithm, plus the ordering vector.
fn build_positives() -> Vec<Positive> {
    let mut out = Vec::new();
    for op_type in OperationType::ALL {
        for algorithm in [Algorithm::Ed25519, Algorithm::P256] {
            let signer: Box<dyn Signer> = match algorithm {
                Algorithm::Ed25519 => Box::new(ed25519(1)),
                Algorithm::P256 => Box::new(p256(2)),
            };
            let core = core_for(*op_type, signer.as_ref());
            let core_bytes = core.encode();
            let operation = sign_operation(&core, signer.as_ref()).expect("signs");
            out.push(Positive {
                name: format!("{}/{}", op_type.as_str(), algorithm.as_str()),
                operation_type: op_type.as_str(),
                algorithm: algorithm.as_str(),
                operation: hex::encode(&operation),
                core: hex::encode(&core_bytes),
                id: core.id().to_hex(),
                public_key: hex::encode(signer.public_key().as_bytes()),
                signing_input: hex::encode(&signing_input(&network(), *op_type, &core_bytes)),
            });
        }
    }

    // Parameters carrying an IPv4 range: the one optional key, present. The
    // vectors above are the same parameters with it absent.
    let signer = ed25519(1);
    let ranged = params().in_ipv4_range("10.42.0.0/16".parse::<Ipv4Range>().expect("allowed"));
    for body in [
        OperationBody::CreateNetwork {
            device: device(1, "phone", Role::Admin, true),
            params: ranged.clone(),
        },
        OperationBody::SetNetwork(ranged),
    ] {
        let op_type = body.operation_type();
        let core = OperationCore::new(
            1_735_689_600_000,
            signer.algorithm(),
            body,
            vec![OperationId::from_bytes([0xaa; 32])],
            signer.key_id(),
            network(),
        )
        .expect("well-formed core");
        let core_bytes = core.encode();
        let operation = sign_operation(&core, &signer).expect("signs");
        out.push(Positive {
            name: format!("{}/ed25519 with an ipv4 range", op_type.as_str()),
            operation_type: op_type.as_str(),
            algorithm: "ed25519",
            operation: hex::encode(&operation),
            core: hex::encode(&core_bytes),
            id: core.id().to_hex(),
            public_key: hex::encode(signer.public_key().as_bytes()),
            signing_input: hex::encode(&signing_input(&network(), op_type, &core_bytes)),
        });
    }

    // A network moving relay: the second optional key, present, with the
    // relay being left pinned and without a pin — its certificate is an array of
    // nothing or one, like the relay's own.
    for pinned in [true, false] {
        let moving = NetworkParams::with_relay(
            vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            Some("https://relay-b.example:443"),
            "example.internal",
            2_592_000,
        )
        .expect("well-formed")
        .leaving(roster::types::Leaving {
            relay: "https://relay-a.example:443".to_owned(),
            relay_cert: pinned.then(|| vec![0x30, 0x82, 0x01, 0x0a]),
            until: 1_735_689_600_000 + 2_592_000 * 1_000,
        })
        .expect("a relay to move to, and one to leave");
        let body = OperationBody::SetNetwork(moving);
        let op_type = body.operation_type();
        let core = OperationCore::new(
            1_735_689_600_000,
            signer.algorithm(),
            body,
            vec![OperationId::from_bytes([0xaa; 32])],
            signer.key_id(),
            network(),
        )
        .expect("well-formed core");
        let core_bytes = core.encode();
        let operation = sign_operation(&core, &signer).expect("signs");
        out.push(Positive {
            name: format!(
                "{}/ed25519 leaving a relay {}",
                op_type.as_str(),
                if pinned { "that was pinned" } else { "that was not pinned" }
            ),
            operation_type: op_type.as_str(),
            algorithm: "ed25519",
            operation: hex::encode(&operation),
            core: hex::encode(&core_bytes),
            id: core.id().to_hex(),
            public_key: hex::encode(signer.public_key().as_bytes()),
            signing_input: hex::encode(&signing_input(&network(), op_type, &core_bytes)),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Negative vectors
// ---------------------------------------------------------------------------

/// One vector per rejection reason.
fn build_negatives() -> Vec<Negative> {
    let signer = ed25519(1);
    let good_core = core_for(OperationType::Demote, &signer);
    let good_core_bytes = good_core.encode();
    let good_operation = sign_operation(&good_core, &signer).expect("signs");
    let good_signature: [u8; 64] = signature_of(&good_operation);
    let body_bytes = good_core.body.encode();
    let author = good_core.author;

    let mut out = Vec::new();

    let mut decode_case = |name: &str, kind: &'static str, bytes: Vec<u8>| {
        out.push(Negative {
            name: name.to_owned(),
            stage: "decode",
            operation: hex::encode(&bytes),
            error_kind: kind,
            public_key: None,
            public_key_alg: None,
        });
    };

    // --- Truncation ------------------------------------------------------
    let mut truncated = good_operation.clone();
    truncated.truncate(good_operation.len().saturating_sub(4));
    decode_case("truncated operation", "unexpected_eof", truncated);

    // --- Canonical form --------------------------------------------------
    decode_case(
        "timestamp in a wider integer than it needs",
        "non_canonical",
        assemble_operation(&core_with_wide_timestamp(&good_core, &body_bytes), &good_signature),
    );
    decode_case(
        "core map keys in alphabetical rather than canonical order",
        "key_ordering",
        assemble_operation(
            &core_with_key_order(&good_core, &body_bytes, ALPHABETICAL_ORDER),
            &good_signature,
        ),
    );
    decode_case(
        "core map with a repeated key",
        "duplicate_key",
        assemble_operation(&core_with_duplicate_key(&good_core, &body_bytes), &good_signature),
    );
    decode_case(
        "core map carrying a key outside the schema",
        "unknown_field",
        assemble_operation(&core_with_extra_key(&good_core, &body_bytes), &good_signature),
    );
    decode_case(
        "core map missing a required key",
        "missing_field",
        assemble_operation(&core_missing_key(&good_core, &body_bytes), &good_signature),
    );

    // --- The relay in the network parameters -----------------------------
    // A network's relay is a signed parameter, so every way of spelling it
    // wrongly has to be refused rather than repaired.
    let set_network = |body: Vec<u8>| {
        let mut core = Vec::new();
        core.push(0xa7);
        push_rest_of_core_head(&mut core, &good_core, &body, "ed25519", "set_network");
        core.push(0x80);
        assemble_operation(&core, &good_signature)
    };

    decode_case(
        "network parameters naming two relays",
        "limit_exceeded",
        set_network(params_map(
            6,
            &relay_field(&["https://a.example", "https://b.example"]),
            false,
        )),
    );
    decode_case(
        "network parameters omitting the relay field",
        "missing_field",
        set_network({
            let mut out = Vec::new();
            out.push(0xa5);
            push_text(&mut out, "ula");
            push_bytes(&mut out, &[0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            push_text(&mut out, "suffix");
            push_text(&mut out, "example.internal");
            push_text(&mut out, "relay_cert");
            out.push(0x80);
            push_text(&mut out, "rendezvous");
            out.push(0x80);
            push_text(&mut out, "snapshot_window");
            out.push(0x01);
            out
        }),
    );
    decode_case(
        "network parameters with the relay after the suffix",
        "key_ordering",
        set_network(params_map(6, &relay_field(&[]), true)),
    );
    decode_case(
        "network parameters repeating the relay",
        "duplicate_key",
        set_network({
            // The entry count still matches the schema, so this reaches the key
            // comparison rather than being refused on the count alone. Some
            // other field is necessarily absent, but the repetition is the more
            // specific complaint.
            let mut out = Vec::new();
            out.push(0xa6);
            push_text(&mut out, "ula");
            push_bytes(&mut out, &[0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            out.extend_from_slice(&relay_field(&[]));
            out.extend_from_slice(&relay_field(&[]));
            push_text(&mut out, "suffix");
            push_text(&mut out, "example.internal");
            push_text(&mut out, "relay_cert");
            out.push(0x80);
            push_text(&mut out, "rendezvous");
            out.push(0x80);
            out
        }),
    );
    decode_case(
        "network parameters with the relay as text rather than an array",
        "type_mismatch",
        set_network(params_map(
            6,
            &{
                let mut field = Vec::new();
                push_text(&mut field, "relay");
                push_text(&mut field, "https://a.example");
                field
            },
            false,
        )),
    );
    decode_case(
        "network parameters with an empty relay address",
        "invalid_value",
        set_network(params_map(6, &relay_field(&[""]), false)),
    );

    // --- The IPv4 range in the network parameters ------------------------
    // The one optional key. Absent is the key left out; every other spelling
    // of absence, and every range that is not allowed, is refused.
    decode_case(
        "network parameters with an empty ipv4 range",
        "invalid_value",
        set_network(params_map_with_ipv4(7, &[&[]], false)),
    );
    decode_case(
        "network parameters with an ipv4 range with host bits set",
        "invalid_value",
        set_network(params_map_with_ipv4(7, &[&[10, 42, 0, 1, 16]], false)),
    );
    decode_case(
        "network parameters with an ipv4 range of four bytes",
        "invalid_value",
        set_network(params_map_with_ipv4(7, &[&[10, 42, 0, 0]], false)),
    );
    decode_case(
        "network parameters with an ipv4 range prefix length of 29",
        "invalid_value",
        set_network(params_map_with_ipv4(7, &[&[10, 42, 0, 0, 29]], false)),
    );
    decode_case(
        "network parameters with an ipv4 range in public space",
        "invalid_value",
        set_network(params_map_with_ipv4(7, &[&[8, 8, 8, 0, 24]], false)),
    );
    decode_case(
        "network parameters with an ipv4 range in loopback",
        "invalid_value",
        set_network(params_map_with_ipv4(7, &[&[127, 0, 0, 0, 8]], false)),
    );
    decode_case(
        "network parameters repeating the ipv4 range",
        "duplicate_key",
        set_network(params_map_with_ipv4(7, &[&[10, 42, 0, 0, 16], &[10, 42, 0, 0, 16]], false)),
    );
    decode_case(
        "network parameters with the ipv4 range after the relay",
        "key_ordering",
        set_network(params_map_with_ipv4(7, &[&[10, 42, 0, 0, 16]], true)),
    );
    decode_case(
        "network parameters with one entry more than the schema",
        "unknown_field",
        // Derived from the schema rather than written as a number: it was `8`,
        // which stopped being *one more* the day the schema grew to eight keys,
        // and the vector went on passing — as a duplicate key, under a name that
        // said otherwise.
        set_network(params_map_with_ipv4(
            u8::try_from(roster::types::NETWORK_PARAMS_SCHEMA.len().saturating_add(1))
                .unwrap_or(u8::MAX),
            &[&[10, 42, 0, 0, 16], &[10, 42, 0, 0, 16], &[10, 42, 0, 0, 16]],
            false,
        )),
    );

    // --- The suffix and the prefix ---------------------------------------
    // Both become configuration of every member's machine: the suffix a rule
    // sending a whole branch of the DNS to this network's resolver, the prefix
    // a route into the tunnel. A signed operation carrying either outside its
    // grammar has to fail to decode, or a network could take a public name or
    // public address space away from the people who joined it.
    decode_case(
        "network parameters with a public suffix",
        "invalid_value",
        set_network(params_map_bounded(&ULA, "azienda.it")),
    );
    decode_case(
        "network parameters with the private namespace alone as the suffix",
        "invalid_value",
        set_network(params_map_bounded(&ULA, "internal")),
    );
    decode_case(
        "network parameters with a suffix other software answers for",
        "invalid_value",
        set_network(params_map_bounded(&ULA, "docker.internal")),
    );
    decode_case(
        "network parameters with an uppercase suffix",
        "invalid_value",
        set_network(params_map_bounded(&ULA, "Casa.internal")),
    );
    decode_case(
        "network parameters with a prefix in global space",
        "invalid_value",
        set_network(params_map_bounded(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0], "casa.internal")),
    );
    decode_case(
        "network parameters with a prefix shorter than a /64",
        "invalid_value",
        set_network(params_map_bounded(&[0xfd, 0x00, 0x00, 0x00], "casa.internal")),
    );

    decode_case("timestamp encoded as text", "type_mismatch", {
        let mut core = Vec::new();
        core.push(0xa7);
        push_text(&mut core, "ts");
        push_text(&mut core, "now");
        push_rest_of_core(&mut core, &good_core, &body_bytes, "ed25519", "demote");
        assemble_operation(&core, &good_signature)
    });
    decode_case("algorithm name that is not valid UTF-8", "invalid_utf8", {
        let mut core = Vec::new();
        core.push(0xa7);
        push_text(&mut core, "ts");
        core.push(0x01);
        push_text(&mut core, "alg");
        // A three-byte text string whose contents are not valid UTF-8.
        core.push(0x63);
        core.extend_from_slice(&[0xff, 0xfe, 0xfd]);
        push_text(&mut core, "body");
        push_bytes(&mut core, &body_bytes);
        push_text(&mut core, "type");
        push_text(&mut core, "demote");
        push_text(&mut core, "author");
        push_bytes(&mut core, author.as_bytes());
        push_text(&mut core, "network");
        push_bytes(&mut core, network().as_bytes());
        push_text(&mut core, "parents");
        core.push(0x80);
        assemble_operation(&core, &good_signature)
    });

    let mut with_trailing = good_operation.clone();
    with_trailing.push(0x00);
    decode_case("valid operation followed by a stray byte", "trailing_data", with_trailing);

    // --- Limits ----------------------------------------------------------
    decode_case("more parents than the bound allows", "limit_exceeded", {
        let mut core = Vec::new();
        core.push(0xa7);
        push_rest_of_core_head(&mut core, &good_core, &body_bytes, "ed25519", "demote");
        // An array header claiming 33 parents, one past the bound.
        core.push(0x98);
        core.push(33);
        for _ in 0..33u8 {
            push_bytes(&mut core, &[0xaa; 32]);
        }
        assemble_operation(&core, &good_signature)
    });

    // --- Type and body ---------------------------------------------------
    decode_case("operation type outside the closed set of seven", "unknown_operation_type", {
        let mut core = Vec::new();
        core.push(0xa7);
        push_rest_of_core_head(&mut core, &good_core, &body_bytes, "ed25519", "delegate");
        core.push(0x80);
        assemble_operation(&core, &good_signature)
    });
    decode_case("an add_device body carried under a rename type", "body_schema", {
        let add_body = body_of(OperationType::AddDevice).encode();
        let mut core = Vec::new();
        core.push(0xa7);
        push_rest_of_core_head(&mut core, &good_core, &add_body, "ed25519", "rename");
        core.push(0x80);
        assemble_operation(&core, &good_signature)
    });
    decode_case("an algorithm this build does not know", "unknown_algorithm", {
        let mut core = Vec::new();
        core.push(0xa7);
        push_rest_of_core_head(&mut core, &good_core, &body_bytes, "ml-dsa-65", "demote");
        core.push(0x80);
        assemble_operation(&core, &good_signature)
    });
    decode_case("a role outside admin and member", "invalid_value", {
        let body = add_device_body_with_role("owner");
        let mut core = Vec::new();
        core.push(0xa7);
        push_rest_of_core_head(&mut core, &good_core, &body, "ed25519", "add_device");
        core.push(0x80);
        assemble_operation(&core, &good_signature)
    });

    // --- Identifiers -----------------------------------------------------
    decode_case("a 128-bit operation id", "identifier_length", {
        let mut out = Vec::new();
        out.push(0xa3);
        push_text(&mut out, "id");
        push_bytes(&mut out, &[0x00; 16]);
        push_text(&mut out, "sig");
        push_bytes(&mut out, &good_signature);
        push_text(&mut out, "core");
        push_bytes(&mut out, &good_core_bytes);
        out
    });
    decode_case(
        "a stated id that does not match the core bytes",
        "id_mismatch",
        assemble_operation_with_id(
            OperationId::from_bytes([0xff; 32]),
            &good_core_bytes,
            &good_signature,
        ),
    );

    // --- Device rules ----------------------------------------------------
    decode_case("one key value serving both signing and transport", "key_reuse", {
        let body = add_device_body_reusing_key();
        let mut core = Vec::new();
        core.push(0xa7);
        push_rest_of_core_head(&mut core, &good_core, &body, "ed25519", "add_device");
        core.push(0x80);
        assemble_operation(&core, &good_signature)
    });
    decode_case("a device carrying only a transport key", "missing_signing_key", {
        let body = add_device_body_without_signing_key();
        let mut core = Vec::new();
        core.push(0xa7);
        push_rest_of_core_head(&mut core, &good_core, &body, "ed25519", "add_device");
        core.push(0x80);
        assemble_operation(&core, &good_signature)
    });
    decode_case("a device carrying no attestation key", "missing_attestation_key", {
        let body = add_device_body_without_attestation_key();
        let mut core = Vec::new();
        core.push(0xa7);
        push_rest_of_core_head(&mut core, &good_core, &body, "ed25519", "add_device");
        core.push(0x80);
        assemble_operation(&core, &good_signature)
    });

    // --- Verification ----------------------------------------------------
    let key_hex = hex::encode(signer.public_key().as_bytes());

    out.push(Negative {
        name: "a signature computed without the domain prefix".to_owned(),
        stage: "verify",
        operation: hex::encode(&{
            let bare = signer.sign(&good_core_bytes).expect("signs");
            let signature: [u8; 64] = bare.as_slice().try_into().expect("64 bytes");
            assemble_operation(&good_core_bytes, &signature)
        }),
        error_kind: "signature_invalid",
        public_key: Some(key_hex.clone()),
        public_key_alg: Some("ed25519"),
    });

    out.push(Negative {
        name: "verified against a key that is not the author".to_owned(),
        stage: "verify",
        operation: hex::encode(&good_operation),
        error_kind: "author_key_mismatch",
        public_key: Some(hex::encode(ed25519(9).public_key().as_bytes())),
        public_key_alg: Some("ed25519"),
    });

    out.push(Negative {
        name: "an all-zero ed25519 public key".to_owned(),
        stage: "verify",
        operation: hex::encode(&good_operation),
        error_kind: "invalid_key",
        public_key: Some(hex::encode(&[0u8; 32])),
        public_key_alg: Some("ed25519"),
    });

    // A P-256 operation whose signature carries the high-s twin of a valid one.
    let p256_signer = p256(2);
    let p256_core = core_for(OperationType::Demote, &p256_signer);
    let p256_operation = sign_operation(&p256_core, &p256_signer).expect("signs");
    let p256_signature = signature_of(&p256_operation);
    out.push(Negative {
        name: "a P-256 signature in high-s form".to_owned(),
        stage: "verify",
        operation: hex::encode(&assemble_operation(
            &p256_core.encode(),
            &malleate(&p256_signature),
        )),
        error_kind: "signature_encoding",
        public_key: Some(hex::encode(p256_signer.public_key().as_bytes())),
        public_key_alg: Some("p256"),
    });

    out
}

/// Pulls the signature out of an encoded operation.
///
/// The wire layout is `{id, sig, core}`, and the signature is the only
/// 64-byte string in it.
fn signature_of(operation: &[u8]) -> [u8; 64] {
    // 0x58 0x40 is the header for a 64-byte string.
    let position = operation
        .windows(2)
        .position(|window| window == [0x58, 0x40])
        .expect("the operation carries a 64-byte signature");
    let start = position.saturating_add(2);
    let slice = operation.get(start..start.saturating_add(64)).expect("64 bytes follow");
    let mut out = [0u8; 64];
    out.copy_from_slice(slice);
    out
}

/// Replaces `s` with `n - s` for a P-256 signature.
fn malleate(signature: &[u8; 64]) -> [u8; 64] {
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let mut out = *signature;
    let s = signature.get(32..64).expect("64 bytes");
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let order_byte = i16::from(*ORDER.get(index).expect("32 bytes"));
        let s_byte = i16::from(*s.get(index).expect("32 bytes"));
        let mut difference =
            order_byte.checked_sub(s_byte).and_then(|value| value.checked_sub(borrow)).unwrap_or(0);
        if difference < 0 {
            difference = difference.saturating_add(256);
            borrow = 1;
        } else {
            borrow = 0;
        }
        if let Some(slot) = out.get_mut(index.saturating_add(32)) {
            *slot = u8::try_from(difference).unwrap_or(0);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Merge vectors
// ---------------------------------------------------------------------------

/// A signed history under construction, addressed by label.
struct Chain {
    /// Label, id and bytes, in creation order.
    entries: Vec<(String, OperationId, Vec<u8>)>,
    /// The network, once the genesis exists.
    pub net: Option<NetworkId>,
    /// Makes otherwise-identical operations distinct.
    nonce: u64,
}

impl Chain {
    /// Starts an empty history.
    fn new() -> Self {
        Self { entries: Vec::new(), net: None, nonce: 0 }
    }

    /// Creates the network. The founding operation carries the zero network
    /// id, because a network is defined by its genesis.
    fn genesis(&mut self, label: &str, seed: u8) {
        let core = OperationCore::new(
            1_735_689_600_000,
            Algorithm::Ed25519,
            OperationBody::CreateNetwork {
                device: device(seed, "phone", Role::Admin, true),
                params: params(),
            },
            vec![],
            ed25519(seed).key_id(),
            NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed genesis");
        let bytes = sign_operation(&core, &ed25519(seed)).expect("signs");
        self.net = Some(NetworkId::from_bytes(*core.id().as_bytes()));
        self.entries.push((label.to_owned(), core.id(), bytes));
    }

    /// Adds an operation hanging off the labelled parents.
    fn op(&mut self, label: &str, seed: u8, parents: &[&str], body: OperationBody) {
        let net = self.net.expect("genesis first");
        self.op_in(label, seed, parents, body, net);
    }

    /// Adds an operation naming an explicit network.
    fn op_in(
        &mut self,
        label: &str,
        seed: u8,
        parents: &[&str],
        body: OperationBody,
        net: NetworkId,
    ) {
        let parent_ids: Vec<OperationId> = parents.iter().map(|name| self.id(name)).collect();
        self.nonce = self.nonce.wrapping_add(1);
        let core = OperationCore::new(
            1_735_689_600_000_u64.wrapping_add(self.nonce),
            Algorithm::Ed25519,
            body,
            parent_ids,
            ed25519(seed).key_id(),
            net,
        )
        .expect("well-formed core");
        let bytes = sign_operation(&core, &ed25519(seed)).expect("signs");
        self.entries.push((label.to_owned(), core.id(), bytes));
    }

    /// The id of a labelled operation.
    fn id(&self, label: &str) -> OperationId {
        self.entries
            .iter()
            .find(|(name, _, _)| name == label)
            .map(|(_, id, _)| *id)
            .unwrap_or_else(|| panic!("no operation labelled `{label}`"))
    }

    /// Every operation, hex.
    fn hex_operations(&self) -> Vec<String> {
        self.entries.iter().map(|(_, _, bytes)| hex::encode(bytes)).collect()
    }

    /// Every operation, verified against the fixture signer that authored it.
    fn verified(&self) -> Vec<roster::sign::VerifiedOperation> {
        self.entries
            .iter()
            .map(|(label, _, bytes)| {
                let raw = roster::sign::RawOperation::decode(bytes)
                    .unwrap_or_else(|error| panic!("`{label}` decodes: {error:?}"));
                let mut found = None;
                for seed in 0u8..=255 {
                    if ed25519(seed).key_id() == raw.core().author {
                        found = raw.verify(&ed25519(seed).public_key()).ok();
                        break;
                    }
                }
                found.unwrap_or_else(|| panic!("`{label}` verifies"))
            })
            .collect()
    }
}

/// The device id of the fixture device with a given seed.
fn seed_device_id(seed: u8) -> DeviceId {
    device(seed, "fixture", Role::Member, false).device_id().expect("has a signing key")
}

/// Turns a built history into a vector, deriving the state it must produce.
fn merge_vector(name: &str, rule: &'static str, chain: &Chain) -> Merge {
    // Offered to a roster rather than assembled into a graph, because that is
    // what an implementation does with these bytes, and because admission now
    // refuses operations that never reach the graph at all. What the roster
    // holds afterwards is what the rest of the vector describes.
    let mut roster = Roster::new();
    let mut refused: Vec<(String, &'static str)> = Vec::new();
    for operation in chain.verified() {
        if let Admission::Refused { operation, reason } = roster.offer_bytes(&operation.to_bytes())
        {
            refused.push((operation.to_hex(), reason.kind()));
        }
    }
    refused.sort_by(|a, b| a.0.cmp(&b.0));

    let dag = roster.dag();
    match derive_with_verdicts(dag) {
        Ok((state, verdicts)) => {
            let mut invalid = Vec::new();
            for (index, operation) in dag.operations().iter().enumerate() {
                if let Some(reason) = verdicts.reason(index) {
                    invalid.push((operation.id().to_hex(), reason.kind()));
                }
            }
            invalid.sort_by(|a, b| a.0.cmp(&b.0));
            Merge {
                name: name.to_owned(),
                rule,
                operations: chain.hex_operations(),
                state: Some(hex::encode(&state.to_bytes())),
                fingerprint: Some(hex::encode(&state.fingerprint())),
                error_kind: None,
                invalid,
                refused,
            }
        }
        Err(error) => Merge {
            name: name.to_owned(),
            rule,
            operations: chain.hex_operations(),
            state: None,
            fingerprint: None,
            error_kind: Some(error.kind()),
            invalid: Vec::new(),
            refused,
        },
    }
}

/// One vector per rule this capability defines.
fn build_merges() -> Vec<Merge> {
    let mut out = Vec::new();

    // Rule 1: revocation wins over a concurrent promotion.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    chain.op(
        "add9",
        1,
        &["add2"],
        OperationBody::AddDevice(device(9, "other-admin", Role::Admin, false)),
    );
    // Two admins. Concurrency between different authors is what these rules are
    // about; one admin signing both branches is a fork, which is judged before
    // any merge rule is reached and would make this vector describe something
    // other than what it names.
    chain.op(
        "promote",
        1,
        &["add9"],
        OperationBody::Promote { device: seed_device_id(2), founder: false },
    );
    chain.op(
        "revoke",
        9,
        &["add9"],
        OperationBody::RevokeDevice { device: seed_device_id(2), reason: "stolen".to_owned() },
    );
    out.push(merge_vector("revocation beats a concurrent promotion", "revocation-wins", &chain));

    // Rule 1 again: a later add does not resurrect a revoked device.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    chain.op(
        "revoke",
        1,
        &["add2"],
        OperationBody::RevokeDevice { device: seed_device_id(2), reason: "stolen".to_owned() },
    );
    chain.op(
        "readd",
        1,
        &["revoke"],
        OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
    );
    out.push(merge_vector("revocation is definitive", "revocation-wins", &chain));

    // Rule 2: concurrent demote beats promote.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin, false)));
    chain.op(
        "add9",
        1,
        &["add2"],
        OperationBody::AddDevice(device(9, "other-admin", Role::Admin, false)),
    );
    chain.op("demote", 1, &["add9"], OperationBody::Demote { device: seed_device_id(2) });
    chain.op(
        "promote",
        9,
        &["add9"],
        OperationBody::Promote { device: seed_device_id(2), founder: false },
    );
    out.push(merge_vector("concurrent demote beats promote", "demote-beats-promote", &chain));

    // Rule 2: a causally later promote re-promotes.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin, false)));
    chain.op("demote", 1, &["add2"], OperationBody::Demote { device: seed_device_id(2) });
    chain.op(
        "promote",
        1,
        &["demote"],
        OperationBody::Promote { device: seed_device_id(2), founder: false },
    );
    out.push(merge_vector("a later promote re-promotes", "demote-beats-promote", &chain));

    // Rule 3: last-writer-wins on rename, broken by id at equal depth.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    chain.op(
        "add9",
        1,
        &["add2"],
        OperationBody::AddDevice(device(9, "other-admin", Role::Admin, false)),
    );
    chain.op(
        "left",
        1,
        &["add9"],
        OperationBody::Rename { device: seed_device_id(2), name: "left".to_owned() },
    );
    chain.op(
        "right",
        9,
        &["add9"],
        OperationBody::Rename { device: seed_device_id(2), name: "right".to_owned() },
    );
    out.push(merge_vector("equal-depth rename tie broken by id", "last-writer-wins", &chain));

    // Rule 3 on network parameters.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op(
        "add9",
        1,
        &["g"],
        OperationBody::AddDevice(device(9, "other-admin", Role::Admin, false)),
    );
    chain.op("left", 1, &["add9"], OperationBody::SetNetwork(params_named("left.internal")));
    chain.op("right", 9, &["add9"], OperationBody::SetNetwork(params_named("right.internal")));
    out.push(merge_vector("concurrent set_network resolves", "last-writer-wins", &chain));

    // The same rule when the two changes carry different IPv4 ranges, and the
    // range is carried into the derived state.
    let ranged = |range: &str| {
        params_named("example.internal").in_ipv4_range(range.parse::<Ipv4Range>().expect("allowed"))
    };
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op(
        "add9",
        1,
        &["g"],
        OperationBody::AddDevice(device(9, "other-admin", Role::Admin, false)),
    );
    chain.op("left", 1, &["add9"], OperationBody::SetNetwork(ranged("10.1.0.0/16")));
    chain.op("right", 9, &["add9"], OperationBody::SetNetwork(ranged("192.168.7.0/24")));
    out.push(merge_vector(
        "concurrent set_network carrying ipv4 ranges resolves",
        "last-writer-wins",
        &chain,
    ));

    // Ancestor-relative validity: a member authors nothing.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    chain.op("add3", 2, &["add2"], OperationBody::AddDevice(device(3, "nas", Role::Member, false)));
    out.push(merge_vector("a member cannot author", "ancestor-relative-validity", &chain));

    // Admission: an operation naming a device its own ancestors do not know can
    // never have an effect, so it is refused rather than admitted and ignored.
    // Without this the room kept for revocations could be filled with
    // revocations of devices nobody ever added.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    chain.op(
        "revoke9",
        1,
        &["add2"],
        OperationBody::RevokeDevice { device: seed_device_id(9), reason: "never added".to_owned() },
    );
    out.push(merge_vector("a revocation of a device never added", "admission", &chain));

    // Admission: the second revocation says nothing the first did not.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    chain.op(
        "revoke2",
        1,
        &["add2"],
        OperationBody::RevokeDevice { device: seed_device_id(2), reason: "lost".to_owned() },
    );
    chain.op(
        "again",
        1,
        &["revoke2"],
        OperationBody::RevokeDevice { device: seed_device_id(2), reason: "lost again".to_owned() },
    );
    out.push(merge_vector("a second revocation of a revoked device", "admission", &chain));

    // Ancestor-relative validity: work done while an admin survives demotion.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin, false)));
    chain.op("add3", 2, &["add2"], OperationBody::AddDevice(device(3, "nas", Role::Member, false)));
    chain.op("demote2", 1, &["add3"], OperationBody::Demote { device: seed_device_id(2) });
    out.push(merge_vector(
        "work done while an admin survives demotion",
        "ancestor-relative-validity",
        &chain,
    ));

    // The causal authorship rule: a backdated operation from a demoted admin.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin, false)));
    chain.op("demote2", 1, &["add2"], OperationBody::Demote { device: seed_device_id(2) });
    chain.op(
        "backdated",
        2,
        &["add2"],
        OperationBody::AddDevice(device(9, "backdoor", Role::Admin, false)),
    );
    out.push(merge_vector(
        "a backdated operation from a demoted admin is void",
        "causal-authorship",
        &chain,
    ));

    // Founder protection.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin, false)));
    chain.op(
        "coup",
        2,
        &["add2"],
        OperationBody::RevokeDevice { device: seed_device_id(1), reason: "coup".to_owned() },
    );
    out.push(merge_vector("an admin cannot revoke a founder", "founder-protection", &chain));

    // Equivocation: one author, two histories. Neither branch takes effect, and
    // the work a *different* author anchored to one of them survives — which is
    // what stops an equivocator from erasing other people's history by signing
    // one late sibling.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op(
        "add9",
        1,
        &["g"],
        OperationBody::AddDevice(device(9, "other-admin", Role::Admin, false)),
    );
    chain.op(
        "fork-left",
        1,
        &["add9"],
        OperationBody::AddDevice(device(2, "left", Role::Member, false)),
    );
    chain.op(
        "fork-right",
        1,
        &["add9"],
        OperationBody::AddDevice(device(3, "right", Role::Member, false)),
    );
    chain.op(
        "theirs",
        9,
        &["fork-left"],
        OperationBody::AddDevice(device(4, "theirs", Role::Member, false)),
    );
    out.push(merge_vector(
        "one author's two concurrent operations take no effect",
        "equivocation",
        &chain,
    ));

    // Founder protection: a founder may retire itself.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin, false)));
    chain.op(
        "retire",
        1,
        &["add2"],
        OperationBody::RevokeDevice { device: seed_device_id(1), reason: "handover".to_owned() },
    );
    out.push(merge_vector("a founder may retire itself", "founder-protection", &chain));

    // Set-level failures.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op(
        "second",
        1,
        &["g"],
        OperationBody::CreateNetwork {
            device: device(2, "other", Role::Admin, true),
            params: params(),
        },
    );
    out.push(set_error_vector("a second create_network", "genesis", &chain, "duplicate_genesis"));

    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op_in(
        "foreign",
        1,
        &["g"],
        OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
        NetworkId::from_bytes([0x99; 32]),
    );
    out.push(set_error_vector(
        "an operation from another network",
        "network-identity",
        &chain,
        "foreign_network",
    ));

    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op_in(
        "orphan",
        1,
        &[],
        OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
        NetworkId::from_bytes([0; 32]),
    );
    out.push(set_error_vector(
        "a parentless non-genesis operation",
        "genesis",
        &chain,
        "parentless_operation",
    ));

    // A set with no genesis at all.
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    chain.op(
        "rename2",
        1,
        &["add2"],
        OperationBody::Rename { device: seed_device_id(2), name: "work".to_owned() },
    );
    // Everything except the founding operation, so the set has no root.
    let without_genesis = Chain {
        entries: chain.entries.iter().skip(1).cloned().collect(),
        net: chain.net,
        nonce: chain.nonce,
    };
    out.push(set_error_vector(
        "an operation set missing its genesis",
        "genesis",
        &without_genesis,
        "missing_genesis",
    ));

    out
}

/// A vector whose operation set must be rejected as a set.
fn set_error_vector(name: &str, rule: &'static str, chain: &Chain, kind: &'static str) -> Merge {
    Merge {
        name: name.to_owned(),
        rule,
        operations: chain.hex_operations(),
        state: None,
        fingerprint: None,
        error_kind: Some(kind),
        invalid: Vec::new(),
        // A set that does not place at all is refused as a set; nothing in it is
        // reached individually.
        refused: Vec::new(),
    }
}

/// Network parameters with a chosen suffix.
fn params_named(suffix: &str) -> NetworkParams {
    NetworkParams::new(vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], suffix, 2_592_000)
        .expect("well-formed")
}

// ---------------------------------------------------------------------------
// Snapshot vectors
// ---------------------------------------------------------------------------

/// Builds a snapshot over the operations a chain's labelled head covers.
fn snapshot_over(chain: &Chain, seq: u64, seed: u8, head: &str, network: NetworkId) -> Vec<u8> {
    let dag = Dag::from_operations(chain.verified()).expect("the set places");
    let head_id = chain.id(head);
    let index = dag.position(&head_id).expect("head is held");
    let state = derive(&dag).expect("derives").to_bytes();
    let body = Snapshot::new(
        seq,
        state,
        vec![head_id],
        vec![dag.depth(index)],
        ed25519(seed).key_id(),
        network,
    )
    .expect("well-formed snapshot");
    sign_snapshot(&body, &ed25519(seed)).expect("signs")
}

/// A short chain whose whole history one snapshot covers.
fn snapshot_chain() -> Chain {
    let mut chain = Chain::new();
    chain.genesis("g", 1);
    chain.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    chain.op(
        "rename2",
        1,
        &["add2"],
        OperationBody::Rename { device: seed_device_id(2), name: "work".to_owned() },
    );
    chain
}

/// One vector per snapshot outcome the specification defines.
fn build_snapshots() -> Vec<SnapshotVector> {
    let chain = snapshot_chain();
    let network = chain.net.expect("genesis first");
    let operations = chain.hex_operations();
    let mut out = Vec::new();

    // Accepted: signed by an admin, and its state is what the history implies.
    out.push(SnapshotVector {
        name: "a snapshot matching the history it covers".to_owned(),
        snapshot: hex::encode(&snapshot_over(&chain, 1, 1, "rename2", network)),
        operations: operations.clone(),
        accepted: true,
        error_kind: None,
        follow_up: None,
        follow_up_error: None,
    });

    // A signature that does not belong to the body.
    let good = snapshot_over(&chain, 1, 1, "rename2", network);
    let raw = roster::snapshot::RawSnapshot::decode(&good).expect("decodes");
    let mut wrong_signature = *raw.signature();
    if let Some(first) = wrong_signature.first_mut() {
        *first ^= 0xff;
    }
    out.push(SnapshotVector {
        name: "a snapshot whose signature does not verify".to_owned(),
        snapshot: hex::encode(&assemble_snapshot(raw.body_bytes(), &wrong_signature)),
        operations: operations.clone(),
        accepted: false,
        error_kind: Some("signature_invalid"),
        follow_up: None,
        follow_up_error: None,
    });

    // A state that disagrees with what the operations imply.
    let liar = {
        let mut fabricated = Chain::new();
        fabricated.genesis("g", 1);
        fabricated.op(
            "add9",
            1,
            &["g"],
            OperationBody::AddDevice(device(9, "ghost", Role::Admin, false)),
        );
        let dag = Dag::from_operations(fabricated.verified()).expect("places");
        derive(&dag).expect("derives").to_bytes()
    };
    let head_id = chain.id("rename2");
    let dag = Dag::from_operations(chain.verified()).expect("places");
    let depth = dag.depth(dag.position(&head_id).expect("held"));
    let lying_body =
        Snapshot::new(1, liar, vec![head_id], vec![depth], ed25519(1).key_id(), network)
            .expect("well-formed");
    out.push(SnapshotVector {
        name: "a snapshot claiming a state the history does not imply".to_owned(),
        snapshot: hex::encode(&sign_snapshot(&lying_body, &ed25519(1)).expect("signs")),
        operations: operations.clone(),
        accepted: false,
        error_kind: Some("snapshot_state_mismatch"),
        follow_up: None,
        follow_up_error: None,
    });

    // Signed by a member rather than an admin.
    out.push(SnapshotVector {
        name: "a snapshot signed by a device that is not an admin".to_owned(),
        snapshot: hex::encode(&snapshot_over(&chain, 1, 2, "rename2", network)),
        operations: operations.clone(),
        accepted: false,
        error_kind: Some("unauthorized_author"),
        follow_up: None,
        follow_up_error: None,
    });

    // A sequence that does not advance.
    out.push(SnapshotVector {
        name: "a snapshot whose sequence number regresses".to_owned(),
        snapshot: hex::encode(&snapshot_over(&chain, 7, 1, "rename2", network)),
        operations: operations.clone(),
        accepted: true,
        error_kind: None,
        follow_up: Some(hex::encode(&snapshot_over(&chain, 4, 1, "add2", network))),
        follow_up_error: Some("snapshot_sequence_regressed"),
    });

    // Two claims at one number: both refused.
    out.push(SnapshotVector {
        name: "two conflicting snapshots at one sequence number".to_owned(),
        snapshot: hex::encode(&snapshot_over(&chain, 5, 1, "rename2", network)),
        operations: operations.clone(),
        accepted: true,
        error_kind: None,
        follow_up: Some(hex::encode(&snapshot_over(&chain, 5, 1, "add2", network))),
        follow_up_error: Some("snapshot_sequence_conflict"),
    });

    // A snapshot belonging to another network.
    let mut other = Chain::new();
    other.genesis("g", 42);
    let foreign_network = other.net.expect("genesis first");
    out.push(SnapshotVector {
        name: "a snapshot from another network".to_owned(),
        snapshot: hex::encode(&snapshot_over(&chain, 1, 1, "rename2", foreign_network)),
        operations: operations.clone(),
        accepted: false,
        error_kind: Some("foreign_network"),
        follow_up: None,
        follow_up_error: None,
    });

    // A node holding nothing adopts it unverified, and must say so.
    out.push(SnapshotVector {
        name: "a snapshot adopted by a node holding nothing it covers".to_owned(),
        snapshot: hex::encode(&snapshot_over(&chain, 1, 1, "rename2", network)),
        operations: Vec::new(),
        accepted: true,
        error_kind: Some("snapshot_unverified"),
        follow_up: None,
        follow_up_error: None,
    });

    out
}

// ---------------------------------------------------------------------------
// Hand-built CBOR
// ---------------------------------------------------------------------------

/// Builds the `set_network` body — the network parameters map — by hand.
///
/// The relay field arrives already encoded, so a defect can be placed in it that
/// the encoder would never produce.
fn params_map(fields: usize, relay: &[u8], misordered: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa0 | u8::try_from(fields).expect("a small map"));
    push_text(&mut out, "ula");
    push_bytes(&mut out, &[0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    if !misordered {
        out.extend_from_slice(relay);
    }
    push_text(&mut out, "suffix");
    push_text(&mut out, "example.internal");
    if misordered {
        // After `suffix` is alphabetical order; canonical order is length-first,
        // which puts a five-byte key before a six-byte one.
        out.extend_from_slice(relay);
    }
    // Ten bytes, so it sits between `suffix` and `snapshot_window`. Absent here,
    // which for this field means an empty array.
    push_text(&mut out, "relay_cert");
    out.push(0x80);
    // Also ten bytes, and `relay_cert` sorts before it: same length, so bytes
    // decide, and `l` precedes `n`.
    push_text(&mut out, "rendezvous");
    out.push(0x80);
    push_text(&mut out, "snapshot_window");
    out.push(0x01);
    out
}

/// Builds the network parameters map by hand with `ipv4` entries.
///
/// Each entry is written as the key `ipv4` and a byte string, after `ula`, or
/// after `relay` when `after_relay`. `entries` is the declared map size.
fn params_map_with_ipv4(entries: u8, ipv4: &[&[u8]], after_relay: bool) -> Vec<u8> {
    let mut out = vec![0xa0 | entries];
    push_text(&mut out, "ula");
    push_bytes(&mut out, &[0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let ranges = |out: &mut Vec<u8>| {
        for value in ipv4 {
            push_text(out, "ipv4");
            push_bytes(out, value);
        }
    };
    if !after_relay {
        ranges(&mut out);
    }
    out.extend_from_slice(&relay_field(&[]));
    if after_relay {
        ranges(&mut out);
    }
    push_text(&mut out, "suffix");
    push_text(&mut out, "example.internal");
    push_text(&mut out, "relay_cert");
    out.push(0x80);
    push_text(&mut out, "rendezvous");
    out.push(0x80);
    push_text(&mut out, "snapshot_window");
    out.push(0x01);
    out
}

/// The prefix every valid vector carries: a unique local `/64`.
const ULA: [u8; 8] = [0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

/// Builds the network parameters map by hand with a chosen prefix and suffix.
///
/// Six entries, canonically ordered, with no relay and no range — so the only
/// thing a case built from this can be refused for is the prefix or the suffix.
fn params_map_bounded(ula: &[u8], suffix: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa6);
    push_text(&mut out, "ula");
    push_bytes(&mut out, ula);
    out.extend_from_slice(&relay_field(&[]));
    push_text(&mut out, "suffix");
    push_text(&mut out, suffix);
    push_text(&mut out, "relay_cert");
    out.push(0x80);
    push_text(&mut out, "rendezvous");
    out.push(0x80);
    push_text(&mut out, "snapshot_window");
    out.push(0x01);
    out
}

/// An encoded `relay` key whose value is an array of the given addresses.
fn relay_field(addresses: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    push_text(&mut out, "relay");
    out.push(0x80 | u8::try_from(addresses.len()).expect("a short array"));
    for address in addresses {
        push_text(&mut out, address);
    }
    out
}

/// The core's fields in alphabetical order, which is *not* canonical order.
const ALPHABETICAL_ORDER: &[&str] = &["alg", "author", "body", "network", "parents", "ts", "type"];

/// Appends a canonically encoded short text string.
fn push_text(out: &mut Vec<u8>, text: &str) {
    let bytes = text.as_bytes();
    assert!(bytes.len() < 24, "only short strings are built by hand here");
    out.push(0x60 | u8::try_from(bytes.len()).expect("under 24"));
    out.extend_from_slice(bytes);
}

/// Appends a canonically encoded byte string.
fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len();
    if len < 24 {
        out.push(0x40 | u8::try_from(len).expect("under 24"));
    } else if len <= usize::from(u8::MAX) {
        out.push(0x58);
        out.push(u8::try_from(len).expect("fits in a byte"));
    } else {
        out.push(0x59);
        out.extend_from_slice(&u16::try_from(len).expect("fits in two bytes").to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

/// Writes `alg`, `body`, `type`, `author` and `network` after `ts`.
fn push_rest_of_core(
    out: &mut Vec<u8>,
    core: &OperationCore,
    body: &[u8],
    alg: &str,
    op_type: &str,
) {
    push_text(out, "alg");
    push_text(out, alg);
    push_text(out, "body");
    push_bytes(out, body);
    push_text(out, "type");
    push_text(out, op_type);
    push_text(out, "author");
    push_bytes(out, core.author.as_bytes());
    push_text(out, "network");
    push_bytes(out, core.network.as_bytes());
    push_text(out, "parents");
    out.push(0x80);
}

/// Writes every core field except `parents`, whose encoding the caller supplies.
fn push_rest_of_core_head(
    out: &mut Vec<u8>,
    core: &OperationCore,
    body: &[u8],
    alg: &str,
    op_type: &str,
) {
    push_text(out, "ts");
    out.push(0x01);
    push_text(out, "alg");
    push_text(out, alg);
    push_text(out, "body");
    push_bytes(out, body);
    push_text(out, "type");
    push_text(out, op_type);
    push_text(out, "author");
    push_bytes(out, core.author.as_bytes());
    push_text(out, "network");
    push_bytes(out, core.network.as_bytes());
    push_text(out, "parents");
}

/// A core whose timestamp uses a two-byte integer where one would do.
fn core_with_wide_timestamp(core: &OperationCore, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa7);
    push_text(&mut out, "ts");
    // 0x19 is the two-byte form; the value 1 fits in the header byte alone.
    out.extend_from_slice(&[0x19, 0x00, 0x01]);
    push_rest_of_core(&mut out, core, body, "ed25519", "demote");
    out
}

/// A core whose keys follow the given order.
fn core_with_key_order(core: &OperationCore, body: &[u8], order: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa7);
    for field in order {
        push_text(&mut out, field);
        match *field {
            "ts" => out.push(0x01),
            "alg" => push_text(&mut out, "ed25519"),
            "body" => push_bytes(&mut out, body),
            "type" => push_text(&mut out, "demote"),
            "author" => push_bytes(&mut out, core.author.as_bytes()),
            "network" => push_bytes(&mut out, core.network.as_bytes()),
            "parents" => out.push(0x80),
            other => panic!("unexpected field {other}"),
        }
    }
    out
}

/// A core carrying `ts` twice and `alg` not at all.
fn core_with_duplicate_key(core: &OperationCore, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa7);
    push_text(&mut out, "ts");
    out.push(0x01);
    push_text(&mut out, "ts");
    out.push(0x02);
    push_text(&mut out, "body");
    push_bytes(&mut out, body);
    push_text(&mut out, "type");
    push_text(&mut out, "demote");
    push_text(&mut out, "author");
    push_bytes(&mut out, core.author.as_bytes());
    push_text(&mut out, "network");
    push_bytes(&mut out, core.network.as_bytes());
    push_text(&mut out, "parents");
    out.push(0x80);
    out
}

/// A core with an eighth field the schema does not define.
fn core_with_extra_key(core: &OperationCore, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa8);
    push_text(&mut out, "ts");
    out.push(0x01);
    push_text(&mut out, "alg");
    push_text(&mut out, "ed25519");
    // "note" sorts with the other four-character keys, after "body".
    push_text(&mut out, "body");
    push_bytes(&mut out, body);
    push_text(&mut out, "note");
    push_text(&mut out, "extra");
    push_text(&mut out, "type");
    push_text(&mut out, "demote");
    push_text(&mut out, "author");
    push_bytes(&mut out, core.author.as_bytes());
    push_text(&mut out, "network");
    push_bytes(&mut out, core.network.as_bytes());
    push_text(&mut out, "parents");
    out.push(0x80);
    out
}

/// A core with six fields where seven are required.
fn core_missing_key(core: &OperationCore, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa6);
    push_text(&mut out, "ts");
    out.push(0x01);
    push_text(&mut out, "alg");
    push_text(&mut out, "ed25519");
    push_text(&mut out, "body");
    push_bytes(&mut out, body);
    push_text(&mut out, "type");
    push_text(&mut out, "demote");
    push_text(&mut out, "author");
    push_bytes(&mut out, core.author.as_bytes());
    push_text(&mut out, "network");
    push_bytes(&mut out, core.network.as_bytes());
    out
}

/// An `add_device` body carrying the given role string.
fn add_device_body_with_role(role: &str) -> Vec<u8> {
    let signing = ed25519(2).public_key().as_bytes().to_vec();
    let transport = ed25519(102).public_key().as_bytes().to_vec();
    device_body(&[(&signing, "signing"), (&transport, "transport")], role)
}

/// An `add_device` body reusing one key value for two purposes.
fn add_device_body_reusing_key() -> Vec<u8> {
    let value = ed25519(2).public_key().as_bytes().to_vec();
    device_body(&[(&value, "signing"), (&value, "transport")], "member")
}

/// An `add_device` body with no signing key.
fn add_device_body_without_signing_key() -> Vec<u8> {
    let transport = ed25519(102).public_key().as_bytes().to_vec();
    let attestation = ed25519(202).public_key().as_bytes().to_vec();
    device_body(&[(&transport, "transport"), (&attestation, "attestation")], "member")
}

/// A device carrying a signing and a transport key and no attestation key: a
/// record that could never date the roster it belongs to.
fn add_device_body_without_attestation_key() -> Vec<u8> {
    let signing = ed25519(103).public_key().as_bytes().to_vec();
    let transport = ed25519(203).public_key().as_bytes().to_vec();
    device_body(&[(&signing, "signing"), (&transport, "transport")], "member")
}

/// Builds a device-specification body by hand.
fn device_body(keys: &[(&Vec<u8>, &str)], role: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa5);
    push_text(&mut out, "keys");
    out.push(0x80 | u8::try_from(keys.len()).expect("a handful"));
    for (value, purpose) in keys {
        out.push(0xa3);
        push_text(&mut out, "alg");
        push_text(&mut out, "ed25519");
        push_text(&mut out, "value");
        push_bytes(&mut out, value);
        push_text(&mut out, "purpose");
        push_text(&mut out, purpose);
    }
    push_text(&mut out, "name");
    push_text(&mut out, "laptop");
    push_text(&mut out, "role");
    push_text(&mut out, role);
    push_text(&mut out, "founder");
    out.push(0xf4);
    push_text(&mut out, "capabilities");
    out.push(0x80);
    out
}

// ---------------------------------------------------------------------------
// JSON, written by hand so the output is byte-stable
// ---------------------------------------------------------------------------

/// Renders the positive corpus.
fn render_positive(vectors: &[Positive]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "  \"format\": \"roster/v1\",");
    let _ = writeln!(out, "  \"kind\": \"positive\",");
    let _ = writeln!(
        out,
        "  \"note\": \"Bytes that must be accepted. Every implementation must reproduce the stated id and verify the signature.\","
    );
    let _ = writeln!(out, "  \"vectors\": [");
    for (index, vector) in vectors.iter().enumerate() {
        let _ = writeln!(out, "    {{");
        let _ = writeln!(out, "      \"name\": \"{}\",", escape(&vector.name));
        let _ = writeln!(out, "      \"operation_type\": \"{}\",", vector.operation_type);
        let _ = writeln!(out, "      \"algorithm\": \"{}\",", vector.algorithm);
        let _ = writeln!(out, "      \"public_key\": \"{}\",", vector.public_key);
        let _ = writeln!(out, "      \"core\": \"{}\",", vector.core);
        let _ = writeln!(out, "      \"signing_input\": \"{}\",", vector.signing_input);
        let _ = writeln!(out, "      \"id\": \"{}\",", vector.id);
        let _ = writeln!(out, "      \"operation\": \"{}\"", vector.operation);
        let last = index.saturating_add(1) == vectors.len();
        let _ = writeln!(out, "    }}{}", if last { "" } else { "," });
    }
    let _ = writeln!(out, "  ]");
    let _ = writeln!(out, "}}");
    out
}

/// Renders the negative corpus.
fn render_negative(vectors: &[Negative]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "  \"format\": \"roster/v1\",");
    let _ = writeln!(out, "  \"kind\": \"negative\",");
    let _ = writeln!(
        out,
        "  \"note\": \"Bytes that must be rejected, with the reason. An implementation that accepts one of these, or rejects it for a different reason, has diverged.\","
    );
    let _ = writeln!(out, "  \"vectors\": [");
    for (index, vector) in vectors.iter().enumerate() {
        let _ = writeln!(out, "    {{");
        let _ = writeln!(out, "      \"name\": \"{}\",", escape(&vector.name));
        let _ = writeln!(out, "      \"stage\": \"{}\",", vector.stage);
        let _ = writeln!(out, "      \"error_kind\": \"{}\",", vector.error_kind);
        if let (Some(key), Some(alg)) = (&vector.public_key, vector.public_key_alg) {
            let _ = writeln!(out, "      \"public_key\": \"{key}\",");
            let _ = writeln!(out, "      \"public_key_alg\": \"{alg}\",");
        }
        let _ = writeln!(out, "      \"operation\": \"{}\"", vector.operation);
        let last = index.saturating_add(1) == vectors.len();
        let _ = writeln!(out, "    }}{}", if last { "" } else { "," });
    }
    let _ = writeln!(out, "  ]");
    let _ = writeln!(out, "}}");
    out
}

/// Renders the merge corpus.
fn render_merge(vectors: &[Merge]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "  \"format\": \"roster/v1\",");
    let _ = writeln!(out, "  \"kind\": \"merge\",");
    let _ = writeln!(
        out,
        "  \"note\": \"Operation sets and the roster each must derive. Every set must be applied in more than one order and give the same result each time; an implementation that derives a different roster, or in a different order derives a different roster, has diverged.\","
    );
    let _ = writeln!(out, "  \"vectors\": [");
    for (index, vector) in vectors.iter().enumerate() {
        let _ = writeln!(out, "    {{");
        let _ = writeln!(out, "      \"name\": \"{}\",", escape(&vector.name));
        let _ = writeln!(out, "      \"rule\": \"{}\",", vector.rule);
        if let Some(kind) = vector.error_kind {
            let _ = writeln!(out, "      \"outcome\": \"error\",");
            let _ = writeln!(out, "      \"error_kind\": \"{kind}\",");
        } else {
            let _ = writeln!(out, "      \"outcome\": \"state\",");
            if let Some(state) = &vector.state {
                let _ = writeln!(out, "      \"state\": \"{state}\",");
            }
            if let Some(fingerprint) = &vector.fingerprint {
                let _ = writeln!(out, "      \"fingerprint\": \"{fingerprint}\",");
            }
        }
        let _ = writeln!(out, "      \"invalid\": [");
        for (position, (id, reason)) in vector.invalid.iter().enumerate() {
            let comma = if position.saturating_add(1) == vector.invalid.len() { "" } else { "," };
            let _ = writeln!(
                out,
                "        {{ \"operation\": \"{id}\", \"reason\": \"{reason}\" }}{comma}"
            );
        }
        let _ = writeln!(out, "      ],");
        let _ = writeln!(out, "      \"refused\": [");
        for (position, (id, reason)) in vector.refused.iter().enumerate() {
            let comma = if position.saturating_add(1) == vector.refused.len() { "" } else { "," };
            let _ = writeln!(
                out,
                "        {{ \"operation\": \"{id}\", \"reason\": \"{reason}\" }}{comma}"
            );
        }
        let _ = writeln!(out, "      ],");
        let _ = writeln!(out, "      \"operations\": [");
        for (position, operation) in vector.operations.iter().enumerate() {
            let comma =
                if position.saturating_add(1) == vector.operations.len() { "" } else { "," };
            let _ = writeln!(out, "        \"{operation}\"{comma}");
        }
        let _ = writeln!(out, "      ]");
        let last = index.saturating_add(1) == vectors.len();
        let _ = writeln!(out, "    }}{}", if last { "" } else { "," });
    }
    let _ = writeln!(out, "  ]");
    let _ = writeln!(out, "}}");
    out
}

/// Renders the snapshot corpus.
fn render_snapshots(vectors: &[SnapshotVector]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{{");
    let _ = writeln!(out, "  \"format\": \"roster/v1\",");
    let _ = writeln!(out, "  \"kind\": \"snapshot\",");
    let _ = writeln!(
        out,
        "  \"note\": \"Snapshots and the verdict each must receive, given the operations a node holds. `accepted` with an `error_kind` of snapshot_unverified means the node may adopt the state but must not treat it as checked.\","
    );
    let _ = writeln!(out, "  \"vectors\": [");
    for (index, vector) in vectors.iter().enumerate() {
        let _ = writeln!(out, "    {{");
        let _ = writeln!(out, "      \"name\": \"{}\",", escape(&vector.name));
        let _ = writeln!(out, "      \"accepted\": {},", vector.accepted);
        if let Some(kind) = vector.error_kind {
            let _ = writeln!(out, "      \"error_kind\": \"{kind}\",");
        }
        if let Some(follow_up) = &vector.follow_up {
            let _ = writeln!(out, "      \"follow_up\": \"{follow_up}\",");
        }
        if let Some(kind) = vector.follow_up_error {
            let _ = writeln!(out, "      \"follow_up_error\": \"{kind}\",");
        }
        let _ = writeln!(out, "      \"operations\": [");
        for (position, operation) in vector.operations.iter().enumerate() {
            let comma =
                if position.saturating_add(1) == vector.operations.len() { "" } else { "," };
            let _ = writeln!(out, "        \"{operation}\"{comma}");
        }
        let _ = writeln!(out, "      ],");
        let _ = writeln!(out, "      \"snapshot\": \"{}\"", vector.snapshot);
        let last = index.saturating_add(1) == vectors.len();
        let _ = writeln!(out, "    }}{}", if last { "" } else { "," });
    }
    let _ = writeln!(out, "  ]");
    let _ = writeln!(out, "}}");
    out
}

/// Escapes the few characters a vector name might carry.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

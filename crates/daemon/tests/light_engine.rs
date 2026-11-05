//! The light member's engine, against a full member's real answers.
//!
//! `light_node::engine` decides what a light member asks and believes, with no
//! input or output of its own. These drive it with roots this daemon signs and
//! answers its full member gives (`daemon::lookup`), so the two halves are held
//! to each other: what the engine asks is what a full member answers.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "a test reports failure by panicking"
)]

use identity::NodeIdentity;
use light_node::channel::Channel;
use light_node::engine::{Engine, LOOKUP_PATIENCE_MS, Output};
use light_node::lookup::{Message, Query};
use roster::id::{DeviceId, NetworkId, OperationId};
use roster::member::{DEFAULT_BUDGET, LightMember};
use roster::roster::Roster;
use roster::sign::sign_operation;
use roster::types::{NetworkParams, OperationBody, OperationCore, Role};

/// A founder's network: its roster, the founder, and the members it admitted.
struct Network {
    roster: Roster,
    founder: NodeIdentity,
    id: NetworkId,
    parents: Vec<OperationId>,
    seq: u64,
}

impl Network {
    /// A network of the founder (full) and `names` (light), with a root.
    fn founded(names: &[&str]) -> (Self, Vec<NodeIdentity>) {
        let founder = NodeIdentity::generate().unwrap();
        let params =
            NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 2_592_000)
                .unwrap();
        let mut network = Self {
            roster: Roster::new(),
            founder,
            id: NetworkId::from_bytes([0; 32]),
            parents: Vec::new(),
            seq: 0,
        };
        let device = network.founder.device_spec("nas", Role::Admin, true, vec![]).unwrap();
        network.act(OperationBody::CreateNetwork { device, params });
        let members: Vec<NodeIdentity> =
            names.iter().map(|_| NodeIdentity::generate().unwrap()).collect();
        for (member, name) in members.iter().zip(names) {
            network.act(OperationBody::AddDevice(
                member.device_spec(*name, Role::Member, false, vec![]).unwrap(),
            ));
        }
        network.root();
        (network, members)
    }

    /// Signs and takes one operation.
    fn act(&mut self, body: OperationBody) {
        self.seq = self.seq.saturating_add(1);
        let core = OperationCore::new(
            self.seq,
            self.founder.signing_key().algorithm(),
            body,
            self.parents.clone(),
            self.founder.signing_key().key_id(),
            self.id,
        )
        .unwrap();
        if self.seq == 1 {
            self.id = NetworkId::from_bytes(*core.id().as_bytes());
        }
        self.parents = vec![core.id()];
        let bytes = sign_operation(&core, self.founder.signer()).unwrap();
        assert!(self.roster.offer_bytes(&bytes).is_accepted());
    }

    /// Signs a root over what it holds, takes it, and gives its bytes.
    fn root(&mut self) -> Vec<u8> {
        let root = daemon::snapshots::sign_over_heads(&self.roster, &self.founder).unwrap();
        assert!(self.roster.offer_snapshot(&root).is_accepted());
        root
    }

    /// Admits one more device, and signs a root over it.
    fn admit_another(&mut self, name: &str) -> Vec<u8> {
        let other = NodeIdentity::generate().unwrap();
        self.act(OperationBody::AddDevice(
            other.device_spec(name, Role::Member, false, vec![]).unwrap(),
        ));
        self.root()
    }

    /// The founder's device id: the full member answering.
    fn full(&self) -> DeviceId {
        self.founder.device_id()
    }

    /// What the founder answers a lookup question, as `Node::answer_lookup`.
    fn answer(&self, body: &[u8]) -> Vec<u8> {
        let Some(Message::Request { id, query }) = Message::decode(body) else {
            panic!("not a question: {body:?}")
        };
        let evidence = match &query {
            Query::Footing(asker, held) => {
                daemon::lookup::footing_of(&self.roster, asker, held.as_ref(), &|_| true)
            }
            Query::RootsAfter(since) => {
                light_node::lookup::encode_roots(&self.roster.roots_after(since))
            }
            other => {
                let state = self.roster.state().unwrap();
                daemon::lookup::resolve(&state, other)
                    .and_then(|device| self.roster.evidence_for(&device))
                    .map_or_else(Vec::new, |evidence| evidence.to_bytes())
            }
        };
        Message::Answer { id, evidence }.encode()
    }

    /// A light member for `member`, against the root held now.
    fn light(&self, member: &NodeIdentity) -> LightMember {
        LightMember::new(
            self.roster.evidence_for(&member.device_id()).unwrap(),
            self.roster.state().unwrap().params,
            DEFAULT_BUDGET,
        )
        .unwrap()
    }
}

/// Every output waiting, in order.
fn drained(engine: &mut Engine) -> Vec<Output> {
    std::iter::from_fn(|| engine.poll_output()).collect()
}

/// The questions among `outputs`, by whom they were sent to.
fn questions(outputs: &[Output]) -> Vec<(DeviceId, Query)> {
    outputs
        .iter()
        .filter_map(|output| match output {
            Output::Send { peer, channel: Channel::Lookup, body } => match Message::decode(body) {
                Some(Message::Request { query, .. }) => Some((*peer, query)),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// Answers every question among `outputs` as the network's full member does.
fn answer_all(engine: &mut Engine, network: &Network, outputs: &[Output], now: u64) {
    for output in outputs {
        if let Output::Send { peer, channel: Channel::Lookup, body } = output {
            engine.lookup(*peer, &network.answer(body), now);
        }
    }
}

#[test]
fn a_root_adopted_is_kept_and_what_it_stands_on_is_asked_of_who_pushed_it() {
    let (mut network, members) = Network::founded(&["sensor"]);
    let mut engine = Engine::new(network.light(&members[0]));
    let newer = network.admit_another("lamp");

    engine.root_pushed(network.full(), &newer, 0);
    let outputs = drained(&mut engine);
    assert_eq!(
        outputs.first(),
        Some(&Output::Keep),
        "kept before anything acts on it: {outputs:?}"
    );
    assert!(outputs.contains(&Output::Reconsider), "sessions judged again under it");
    assert!(outputs.contains(&Output::StateChanged));
    let asked = questions(&outputs);
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(asked[0].0, network.full());
    assert!(matches!(asked[0].1, Query::Footing(device, None) if device == members[0].device_id()));

    // Answered whole the first time, then by its digest alone.
    answer_all(&mut engine, &network, &outputs, 1);
    assert!(!engine.is_busy(), "nothing more owed");
    // An act that hands the light member no other full member.
    network.act(OperationBody::SetDevice {
        device: members[0].device_id(),
        change: roster::leaf::SettingsChange {
            ipv4: Some(Some(9_u32.to_be_bytes())),
            ..roster::leaf::SettingsChange::default()
        },
    });
    let newest = network.root();
    engine.root_pushed(network.full(), &newest, 2);
    let outputs = drained(&mut engine);
    let asked = questions(&outputs);
    assert!(matches!(asked[0].1, Query::Footing(_, Some(_))), "{asked:?}");
    let Some(Output::Send { body, .. }) =
        outputs.iter().find(|output| matches!(output, Output::Send { .. }))
    else {
        panic!("{outputs:?}")
    };
    let Some(Message::Answer { evidence, .. }) = Message::decode(&network.answer(body)) else {
        panic!()
    };
    assert_eq!(evidence.len(), 32, "a footing unchanged comes back as its digest");
    answer_all(&mut engine, &network, &outputs, 3);

    // The root named this member, so its proof is renewed next, of its contact.
    let outputs = drained(&mut engine);
    let asked = questions(&outputs);
    assert!(matches!(asked.as_slice(), [(_, Query::Ipv6(_))]), "{asked:?}");
    answer_all(&mut engine, &network, &outputs, 4);
    assert!(drained(&mut engine).contains(&Output::Renewed));
    assert!(!engine.is_busy(), "nothing more owed");
}

#[test]
fn a_footing_unanswered_is_asked_of_the_next_member_met() {
    let (mut network, members) = Network::founded(&["sensor"]);
    let mut engine = Engine::new(network.light(&members[0]));
    // The first session asks it at once.
    let other = DeviceId::from_bytes([9; 32]);
    engine.session_opened(other, 0);
    let asked = questions(&drained(&mut engine));
    assert!(
        matches!(asked.as_slice(), [(peer, Query::Footing(..))] if *peer == other),
        "{asked:?}"
    );

    // Nobody answers.
    engine.tick(LOOKUP_PATIENCE_MS);
    let outputs = drained(&mut engine);
    assert!(questions(&outputs).is_empty(), "{outputs:?}");
    assert!(!engine.is_busy());

    // The next member met is asked, and answers.
    engine.session_opened(network.full(), LOOKUP_PATIENCE_MS + 1);
    let outputs = drained(&mut engine);
    let asked = questions(&outputs);
    assert!(matches!(asked.as_slice(), [(peer, Query::Footing(..))] if *peer == network.full()));
    answer_all(&mut engine, &network, &outputs, LOOKUP_PATIENCE_MS + 2);

    // And once taken, a session opening asks nothing.
    engine.session_opened(DeviceId::from_bytes([8; 32]), LOOKUP_PATIENCE_MS + 3);
    assert!(questions(&drained(&mut engine)).is_empty());
    let _ = network.root();
}

#[test]
fn a_root_that_skips_some_has_the_chain_asked_and_every_root_taken() {
    let (mut network, members) = Network::founded(&["sensor"]);
    let mut engine = Engine::new(network.light(&members[0]));
    let held = engine.member().current().unwrap();
    let _missed = network.admit_another("lamp");
    let latest = network.admit_another("door");

    engine.root_pushed(network.full(), &latest, 0);
    let outputs = drained(&mut engine);
    let asked = questions(&outputs);
    assert_eq!(asked, vec![(network.full(), Query::RootsAfter(held))], "{outputs:?}");

    answer_all(&mut engine, &network, &outputs, 1);
    let outputs = drained(&mut engine);
    assert_ne!(engine.member().current(), Some(held), "caught up");
    assert!(outputs.contains(&Output::Keep) && outputs.contains(&Output::Reconsider));
    // Then what it stands on, of the same peer.
    let asked = questions(&outputs);
    assert!(matches!(asked.as_slice(), [(peer, Query::Footing(..))] if *peer == network.full()));
}

#[test]
fn a_proof_is_renewed_from_the_contact_first_and_an_answer_from_anyone_else_is_ignored() {
    let (network, members) = Network::founded(&["sensor"]);
    let mut engine = Engine::new(network.light(&members[0]));
    let contact = engine.member().contact();
    let stranger = DeviceId::from_bytes([7; 32]);
    engine.session_opened(stranger, 0);
    let _ = drained(&mut engine);
    engine.tick(LOOKUP_PATIENCE_MS);
    let _ = drained(&mut engine);

    engine.refused_as_a_stranger(LOOKUP_PATIENCE_MS + 1);
    let outputs = drained(&mut engine);
    let asked = questions(&outputs);
    assert!(matches!(asked.as_slice(), [(peer, Query::Ipv6(_))] if *peer == contact), "{asked:?}");

    // The same answer, from a member that was not asked, is not taken.
    let Output::Send { body, .. } =
        outputs.iter().find(|output| matches!(output, Output::Send { .. })).unwrap()
    else {
        panic!()
    };
    let answer = network.answer(body);
    engine.lookup(stranger, &answer, LOOKUP_PATIENCE_MS + 2);
    assert!(!drained(&mut engine).contains(&Output::Renewed));

    engine.lookup(contact, &answer, LOOKUP_PATIENCE_MS + 3);
    let outputs = drained(&mut engine);
    assert!(outputs.contains(&Output::Renewed), "{outputs:?}");
    assert_eq!(outputs.first(), Some(&Output::Keep));
}

#[test]
fn a_question_from_a_peer_is_answered_with_nothing() {
    let (network, members) = Network::founded(&["sensor"]);
    let mut engine = Engine::new(network.light(&members[0]));
    let asking = Message::Request { id: 4, query: Query::Name("nas".into()) }.encode();
    engine.lookup(network.full(), &asking, 0);
    assert_eq!(
        drained(&mut engine),
        vec![Output::Send {
            peer: network.full(),
            channel: Channel::Lookup,
            body: Message::Answer { id: 4, evidence: Vec::new() }.encode(),
        }]
    );
}

#[test]
fn a_member_is_found_by_asking_the_members_in_session() {
    let (network, members) = Network::founded(&["sensor", "lamp"]);
    let mut engine = Engine::new(network.light(&members[0]));
    engine.session_opened(network.full(), 0);
    let outputs = drained(&mut engine);
    answer_all(&mut engine, &network, &outputs, 1);
    let _ = drained(&mut engine);

    let query = Query::Name("lamp".into());
    engine.find(query.clone(), 2);
    let outputs = drained(&mut engine);
    answer_all(&mut engine, &network, &outputs, 3);
    let outputs = drained(&mut engine);
    assert!(
        outputs.contains(&Output::Found { query, device: Some(members[1].device_id()) }),
        "{outputs:?}"
    );
    assert!(engine.member().state().devices.contains_key(&members[1].device_id()), "learned");
}

/// A board's keys, as it makes them: its signing, transport and attestation
/// keys, public halves.
fn keys_of(board: &NodeIdentity) -> Vec<roster::types::KeyEntry> {
    board.device_spec("board", Role::Member, false, vec![]).unwrap().keys
}

/// A board provisioned before it is admitted: it starts from the network's
/// root, asks for its proof and is not given one; once admitted, it takes the
/// newer roots, is given its proof, and is a member.
#[test]
fn a_board_provisioned_before_its_admission_joins_once_admitted() {
    let (mut network, _members) = Network::founded(&["sensor"]);
    let board = NodeIdentity::generate().unwrap();
    let state = network.roster.state().unwrap();
    let held = network.roster.snapshot().unwrap().to_bytes();
    let member = LightMember::awaiting(
        keys_of(&board),
        &held,
        &state.devices.root(),
        state.params.clone(),
        DEFAULT_BUDGET,
    )
    .unwrap();
    assert!(!member.is_admitted());
    assert!(member.shown().is_empty(), "it shows nothing");
    let mut engine = Engine::new(member);

    // Not yet admitted: asked, the full member knows nothing of it.
    engine.session_opened(network.full(), 0);
    let mut outputs = drained(&mut engine);
    for _ in 0..4 {
        answer_all(&mut engine, &network, &outputs, 1);
        outputs = drained(&mut engine);
    }
    assert!(!engine.member().is_admitted());

    // Admitted, in a batch of one; the root after it pushed.
    network.act(OperationBody::AddDevice(
        board.device_spec("board", Role::Member, false, vec![]).unwrap(),
    ));
    let newer = network.root();
    engine.root_pushed(network.full(), &newer, 2);
    let mut renewed = false;
    for at in 3..12 {
        let outputs = drained(&mut engine);
        renewed |= outputs.contains(&Output::Renewed);
        if outputs.is_empty() {
            engine.session_opened(network.full(), at);
            continue;
        }
        answer_all(&mut engine, &network, &outputs, at);
    }
    renewed |= drained(&mut engine).contains(&Output::Renewed);
    assert!(renewed, "given its proof");
    assert!(engine.member().is_admitted());
    assert_eq!(engine.member().device(), board.device_id());
    assert!(!engine.member().shown().is_empty(), "and shows it from now on");
}

/// A leaf naming the board's device but other keys than it made is not taken
/// as its own: its transport key would be someone else's.
#[test]
fn a_board_takes_no_leaf_naming_other_keys_than_it_made() {
    let (mut network, _members) = Network::founded(&["sensor"]);
    let board = NodeIdentity::generate().unwrap();
    let other = NodeIdentity::generate().unwrap();
    let state = network.roster.state().unwrap();
    let held = network.roster.snapshot().unwrap().to_bytes();
    // Its signing key, and another device's transport key.
    let mut keys = keys_of(&board);
    let foreign = keys_of(&other);
    for entry in &mut keys {
        if entry.purpose == roster::types::KeyPurpose::Transport {
            *entry = foreign.iter().find(|key| key.purpose == entry.purpose).unwrap().clone();
        }
    }
    let mut member = LightMember::awaiting(
        keys,
        &held,
        &state.devices.root(),
        state.params.clone(),
        DEFAULT_BUDGET,
    )
    .unwrap();
    network.act(OperationBody::AddDevice(
        board.device_spec("board", Role::Member, false, vec![]).unwrap(),
    ));
    let newer = network.root();
    assert!(member.offer_root(&newer).is_ok());
    let evidence = network.roster.evidence_for(&board.device_id()).unwrap();
    assert!(member.renew(evidence).is_err(), "the leaf names a transport key it did not make");
    assert!(!member.is_admitted());
}

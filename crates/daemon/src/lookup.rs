//! A full member's half of lookups: whom its state names, and what it hands a
//! light member that asks what it stands on. The messages, and what the asker
//! believes of an answer, are `light_node::lookup`'s.

pub use light_node::lookup::*;

use roster::id::DeviceId;
use roster::state::RosterState;

/// The member a full member's state names for `query`, if any.
#[must_use]
pub fn resolve(state: &RosterState, query: &Query) -> Option<DeviceId> {
    match query {
        // Asked of the state's indexes, not of every device: a lookup is
        // answered for whoever asks, and a fleet has a million of them.
        Query::Name(name) => state.devices.named(name).first().map(|leaf| leaf.record.id),
        Query::Ipv6(address) => {
            let prefix = tunnel::Prefix::from_parameter(&state.params.ula).ok()?;
            let mut router = crate::router::Router::new(prefix);
            router.follow_state(state, &DeviceId::from_bytes([0; 32]));
            router.member_at(*address)
        }
        Query::Ipv4(address) => tunnel::Ipv4Holdings::of_state(state).holder(*address),
        Query::RootsAfter(_) | Query::Footing(..) => None,
    }
}

/// The evidence of the full members a full member holding `roster` hands the
/// light member `asker`, as `seeking::handed` chooses them: its anchors that
/// are full members, where the network names any; otherwise the full members
/// `recent` ranks first. Each against the root `roster` holds.
#[must_use]
pub fn handed_evidence(
    roster: &roster::roster::Roster,
    asker: &DeviceId,
    recent: &dyn Fn(&DeviceId) -> bool,
) -> Vec<Vec<u8>> {
    let copied;
    let state = match roster.held_state() {
        Some(state) => state,
        None => match roster.snapshot().and_then(|held| roster.state_for_root(&held.body().root)) {
            Some((_, state)) => {
                copied = state;
                &copied
            }
            None => return Vec::new(),
        },
    };
    let full = |device: &DeviceId| {
        state.devices.get(device).is_some_and(|leaf| leaf.settings.mode == roster::leaf::Mode::Full)
    };
    let anchors: Vec<DeviceId> =
        state.params.anchors.iter().filter(|anchor| full(anchor)).copied().collect();
    // Only where there are no anchors is every full member a candidate: a
    // network that names anchors is the large one, where nobody walks them all.
    let fulls: Vec<DeviceId> = if anchors.is_empty() {
        state
            .devices
            .iter()
            .filter(|(_, leaf)| leaf.settings.mode == roster::leaf::Mode::Full)
            .map(|(device, _)| device)
            .collect()
    } else {
        Vec::new()
    };
    crate::seeking::handed(asker, &anchors, &fulls, recent)
        .iter()
        .map(|device| crate::snapshots::evidence_of(roster, device))
        .filter(|evidence| !evidence.is_empty())
        .collect()
}

/// What a full member holding `roster` answers the light member `asker` that
/// asks what it stands on: the parameters and the devices' root under the
/// root held, and [`handed_evidence`]; or the digest alone, where it is
/// `held`, the digest of the footing the light member last took. Empty where
/// it holds no root.
///
/// Asked by every light member that takes a root, after every act: answered
/// whole, it was some 9 KB a light member per act at a hundred thousand of
/// them, for parameters and full members that had not changed
/// (`daemon::simulator`).
#[must_use]
pub fn footing_of(
    roster: &roster::roster::Roster,
    asker: &DeviceId,
    held: Option<&[u8; 32]>,
    recent: &dyn Fn(&DeviceId) -> bool,
) -> Vec<u8> {
    let answer = |footing: Footing| {
        let digest = footing.digest();
        if held == Some(&digest) { digest.to_vec() } else { footing.encode() }
    };
    let footing = |state: &RosterState| Footing {
        devices_root: state.devices.root(),
        params: state.params.to_bytes(),
        fulls: handed_evidence(roster, asker, recent),
    };
    // Read where it is kept: asked of a full member by every light member
    // that takes a root, so a copy of the state each time was a copy per light
    // member per act (`roster::roster::Roster::held_state`).
    if let Some(state) = roster.held_state() {
        return answer(footing(state));
    }
    roster
        .snapshot()
        .and_then(|held| roster.state_for_root(&held.body().root))
        .map_or_else(Vec::new, |(_, state)| answer(footing(&state)))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use identity::NodeIdentity;
    use roster::id::NetworkId;
    use roster::member::{DEFAULT_BUDGET, LightMember};
    use roster::roster::Roster;
    use roster::sign::sign_operation;
    use roster::types::{NetworkParams, OperationBody, OperationCore, Role};

    use super::*;

    /// A founder's roster of three members, with a root over it, and the three.
    fn rooted() -> (Roster, Vec<NodeIdentity>) {
        let founder = NodeIdentity::generate().unwrap();
        let params =
            NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 2_592_000)
                .unwrap();
        let mut roster = Roster::new();
        let mut parents = Vec::new();
        let mut network = NetworkId::from_bytes([0; 32]);
        let members: Vec<NodeIdentity> =
            (0..3).map(|_| NodeIdentity::generate().unwrap()).collect();
        let bodies = std::iter::once(OperationBody::CreateNetwork {
            device: founder.device_spec("nas", Role::Admin, true, vec![]).unwrap(),
            params,
        })
        .chain(members.iter().zip(["laptop", "phone", "sensor"]).map(|(member, name)| {
            OperationBody::AddDevice(member.device_spec(name, Role::Member, false, vec![]).unwrap())
        }))
        // The phone given the block's first host.
        .chain(std::iter::once(OperationBody::SetDevice {
            device: members.get(1).unwrap().device_id(),
            change: roster::leaf::SettingsChange {
                ipv4: Some(Some(1_u32.to_be_bytes())),
                ..roster::leaf::SettingsChange::default()
            },
        }));
        for (index, body) in bodies.enumerate() {
            let core = OperationCore::new(
                u64::try_from(index).unwrap().saturating_add(1),
                founder.signing_key().algorithm(),
                body,
                parents.clone(),
                founder.signing_key().key_id(),
                network,
            )
            .unwrap();
            if index == 0 {
                network = NetworkId::from_bytes(*core.id().as_bytes());
            }
            parents = vec![core.id()];
            assert!(
                roster.offer_bytes(&sign_operation(&core, founder.signer()).unwrap()).is_accepted()
            );
        }
        let root = crate::snapshots::sign_over_heads(&roster, &founder).unwrap();
        assert!(roster.offer_snapshot(&root).is_accepted());
        (roster, members)
    }

    fn light_for(roster: &Roster, device: &DeviceId) -> LightMember {
        LightMember::new(
            roster.evidence_for(device).unwrap(),
            roster.state().unwrap().params,
            DEFAULT_BUDGET,
        )
        .unwrap()
    }

    #[test]
    fn a_full_member_resolves_by_name_ipv6_and_ipv4_and_a_light_one_believes_it() {
        let (roster, members) = rooted();
        let state = roster.state().unwrap();
        let phone = members.get(1).unwrap().device_id();
        let prefix = tunnel::Prefix::from_parameter(&state.params.ula).unwrap();
        let ipv4 = tunnel::Ipv4Holdings::of_state(&state).of(&phone).unwrap();
        for query in [
            Query::Name("PHONE".into()),
            Query::Ipv6(tunnel::address_of(&phone, &prefix)),
            Query::Ipv4(ipv4),
        ] {
            assert_eq!(resolve(&state, &query), Some(phone), "{query:?}");
            let mut light = light_for(&roster, &members.first().unwrap().device_id());
            let evidence = roster.evidence_for(&phone).unwrap().to_bytes();
            assert_eq!(take_answer(&mut light, &query, &evidence), Ok(phone));
            assert!(light.state().devices.contains_key(&phone), "and learns it");
        }
    }

    #[test]
    fn a_false_answer_is_refused_and_the_peer_stays_unknown() {
        let (roster, members) = rooted();
        let phone = members.get(1).unwrap().device_id();
        let sensor = members.get(2).unwrap().device_id();
        let mut light = light_for(&roster, &members.first().unwrap().device_id());

        // Asked for the phone, answered with the sensor's evidence: genuine, and
        // not what was asked.
        let wrong = roster.evidence_for(&sensor).unwrap().to_bytes();
        assert_eq!(
            take_answer(&mut light, &Query::Name("phone".into()), &wrong),
            Err(Refusal::NotAsked)
        );
        assert!(!light.state().devices.contains_key(&phone));
        assert!(!light.state().devices.contains_key(&sensor), "nor is the other learned");

        // And nothing known is said as such.
        assert_eq!(
            take_answer(&mut light, &Query::Name("phone".into()), &[]),
            Err(Refusal::Unknown)
        );
    }

    #[test]
    fn roots_read_back_as_written() {
        let roots = vec![vec![1, 2, 3], Vec::new(), vec![9; 300]];
        assert_eq!(decode_roots(&encode_roots(&roots)), Some(roots));
        assert_eq!(decode_roots(&[0, 0, 0, 5, 1]), None, "a root cut short");
    }

    #[test]
    fn a_footing_reads_back_as_written() {
        let footing = Footing {
            devices_root: [7; 32],
            params: vec![1, 2, 3],
            fulls: vec![vec![4; 40], vec![5; 2]],
        };
        assert_eq!(Footing::decode(&footing.encode()), Some(footing.clone()));
        let cut = footing.encode().get(..20).map(<[u8]>::to_vec).unwrap();
        assert_eq!(Footing::decode(&cut), None, "cut short");
        let asked =
            Message::Request { id: 3, query: Query::Footing(DeviceId::from_bytes([2; 32]), None) };
        assert_eq!(Message::decode(&asked.encode()), Some(asked));
        let holding = Message::Request {
            id: 3,
            query: Query::Footing(DeviceId::from_bytes([2; 32]), Some([8; 32])),
        };
        assert_eq!(Message::decode(&holding.encode()), Some(holding));
        let after = Message::Request { id: 4, query: Query::RootsAfter([9; 32]) };
        assert_eq!(Message::decode(&after.encode()), Some(after.clone()));
        let cut = after.encode().get(..20).map(<[u8]>::to_vec).unwrap();
        assert_eq!(Message::decode(&cut), None, "a root cut short");
    }

    /// A founder signs a change, and a root over it.
    fn signed_on(roster: &mut Roster, founder: &NodeIdentity, body: OperationBody) -> Vec<u8> {
        let state = roster.state().unwrap();
        let core = OperationCore::new(
            100,
            founder.signing_key().algorithm(),
            body,
            roster.heads(),
            founder.signing_key().key_id(),
            state.network,
        )
        .unwrap();
        assert!(roster.offer_bytes(&founder.sign_operation(&core).unwrap()).is_accepted());
        let root = crate::snapshots::sign_over_heads(roster, founder).unwrap();
        assert!(roster.offer_snapshot(&root).is_accepted());
        root
    }

    #[test]
    fn a_light_member_is_handed_full_members_and_follows_the_parameters() {
        let (mut roster, members, founder) = rooted_with_founder();
        let laptop = members.first().unwrap().device_id();
        let sensor = members.get(2).unwrap().device_id();
        let mut light = light_for(&roster, &sensor);

        // A home network: full members to turn to besides its contact.
        let answer = footing_of(&roster, &sensor, None, &|_| false);
        let footing = Footing::decode(&answer).unwrap();
        assert!(take_footing(&mut light, &footing), "it keeps what it was handed");
        let kept = light.known_fulls();
        assert!(!kept.is_empty(), "something besides the admin that admitted it");
        assert!(!kept.contains(&sensor) && !kept.contains(&light.contact()));

        // The laptop named an anchor, with a root over it: the parameters follow
        // that root, and the anchor's evidence comes with them.
        let params = roster.state().unwrap().params.with_anchors(vec![laptop]).unwrap();
        let root = signed_on(&mut roster, &founder, OperationBody::SetNetwork(params));
        light.offer_root(&root).unwrap();
        let footing = Footing::decode(&footing_of(&roster, &sensor, None, &|_| false)).unwrap();
        assert!(take_footing(&mut light, &footing));
        assert_eq!(light.params().anchors, vec![laptop], "the anchor list reached it");
        assert!(light.known_fulls().contains(&laptop), "with the anchor's leaf");

        // Asked again with the digest of what it took: nothing it keeps changed
        // — a device that is not its anchor was renamed — so the digest alone
        // comes back, though a root has been published since.
        let held = footing.digest();
        let other = members.get(1).unwrap().device_id();
        let renamed = OperationBody::Rename { device: other, name: "studio".to_owned() };
        let root = signed_on(&mut roster, &founder, renamed);
        light.offer_root(&root).unwrap();
        assert_eq!(footing_of(&roster, &sensor, Some(&held), &|_| false), held.to_vec());

        // The parameters changed: the footing comes back whole.
        let params = roster.state().unwrap().params.with_anchors(Vec::new()).unwrap();
        let root = signed_on(&mut roster, &founder, OperationBody::SetNetwork(params));
        light.offer_root(&root).unwrap();
        let answer = footing_of(&roster, &sensor, Some(&held), &|_| false);
        let whole = Footing::decode(&answer).expect("the footing, whole");
        assert_ne!(whole.digest(), held);
    }

    #[test]
    fn a_forged_footing_is_not_believed() {
        let (roster, members, _founder) = rooted_with_founder();
        let sensor = members.get(2).unwrap().device_id();
        let mut light = light_for(&roster, &sensor);
        let before = light.params().clone();
        let mut footing = Footing::decode(&footing_of(&roster, &sensor, None, &|_| false)).unwrap();

        // Parameters that do not make the root held, and a leaf altered.
        let mut changed = before.clone();
        changed.suffix = "elsewhere.internal".into();
        footing.params = changed.to_bytes();
        for evidence in &mut footing.fulls {
            let mut shown = roster::membership::Evidence::from_bytes(evidence).unwrap();
            shown.leaf.record.name = "intruder".into();
            *evidence = shown.to_bytes();
        }
        assert!(!take_footing(&mut light, &footing), "nothing taken");
        assert_eq!(light.params(), &before);
        assert!(light.known_fulls().is_empty());
    }

    /// The fixture of `rooted`, with the founder that signs for it.
    fn rooted_with_founder() -> (Roster, Vec<NodeIdentity>, NodeIdentity) {
        let founder = NodeIdentity::generate().unwrap();
        let params =
            NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 2_592_000)
                .unwrap();
        let mut roster = Roster::new();
        let mut parents = Vec::new();
        let mut network = NetworkId::from_bytes([0; 32]);
        let members: Vec<NodeIdentity> =
            (0..3).map(|_| NodeIdentity::generate().unwrap()).collect();
        let bodies = std::iter::once(OperationBody::CreateNetwork {
            device: founder.device_spec("nas", Role::Admin, true, vec![]).unwrap(),
            params,
        })
        .chain(members.iter().zip(["laptop", "phone", "sensor"]).map(|(member, name)| {
            OperationBody::AddDevice(member.device_spec(name, Role::Member, false, vec![]).unwrap())
        }));
        for (index, body) in bodies.enumerate() {
            let core = OperationCore::new(
                u64::try_from(index).unwrap().saturating_add(1),
                founder.signing_key().algorithm(),
                body,
                parents.clone(),
                founder.signing_key().key_id(),
                network,
            )
            .unwrap();
            if index == 0 {
                network = NetworkId::from_bytes(*core.id().as_bytes());
            }
            parents = vec![core.id()];
            assert!(
                roster.offer_bytes(&sign_operation(&core, founder.signer()).unwrap()).is_accepted()
            );
        }
        let root = crate::snapshots::sign_over_heads(&roster, &founder).unwrap();
        assert!(roster.offer_snapshot(&root).is_accepted());
        (roster, members, founder)
    }
}

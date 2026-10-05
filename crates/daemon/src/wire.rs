//! The DNS wire format around [`crate::names`].
//!
//! Every rule lives in `names`. This turns a query into a question and an answer
//! into bytes, and holds no policy of its own — if a decision about what a name
//! means appears here, it is in the wrong module.
//!
//! # It answers, and never asks
//!
//! There is no resolver client in this crate. A query it cannot answer is
//! answered as non-existent, never passed on. The resolution rule scopes this
//! to the network's suffix, so a query about anything else should not arrive at
//! all; one that does is a sign the rule is wrong, and forwarding it would hide
//! exactly that.

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use roster::state::RosterState;

use crate::limits;
pub use crate::names::Ipv4View;
use crate::names::{Answer, answer};

/// How long a resolver may keep an answer.
///
/// Short. A device's address is stable while it is in the roster, but a device
/// *leaving* the roster must stop resolving promptly, and a long cache would
/// hold a departed device's name alive on the machine after the roster had
/// forgotten it. The rule that revocation takes effect immediately has to survive
/// the resolver's own cache as well as ours.
const TTL: u32 = 30;

/// Turns a query into a response.
///
/// `None` when the bytes are not a query this should answer at all — malformed,
/// oversized, or a response rather than a question. Nothing is sent back in that
/// case, because replying to a message we could not parse means replying to
/// whatever the sender wanted us to think it was.
#[must_use]
pub fn respond(state: &RosterState, ipv4: &Ipv4View, query: &[u8]) -> Option<Vec<u8>> {
    if query.len() > limits::MAX_DNS_MESSAGE {
        return None;
    }
    let request = Message::from_vec(query).ok()?;
    if request.metadata.message_type != MessageType::Query
        || request.metadata.op_code != OpCode::Query
    {
        return None;
    }

    let question = request.queries.first()?.clone();
    let name = question.name().to_ascii();

    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    // Authoritative: this daemon is the whole truth about its suffix, and saying
    // otherwise invites a resolver to look for a better answer elsewhere.
    response.metadata.authoritative = true;
    response.add_query(question.clone());

    match answer(state, ipv4, &name) {
        Answer::Device { v6, .. } if question.query_type() == RecordType::AAAA => {
            response.add_answer(Record::from_rdata(
                question.name().clone(),
                TTL,
                RData::AAAA(AAAA(v6)),
            ));
        }
        // A client that decided the machine has no IPv6 asks only for this, and
        // an address that works is what lets it reach a peerfectly name at all.
        Answer::Device { v4: Some(v4), .. } if question.query_type() == RecordType::A => {
            response.add_answer(Record::from_rdata(question.name().clone(), TTL, RData::A(A(v4))));
        }
        // The name exists, but not with the record type asked for — or it holds
        // no IPv4 address that can be answered here. An empty success, not a
        // denial: saying the name does not exist would be a lie that a resolver
        // is entitled to cache.
        Answer::Device { .. } => {}
        Answer::NonExistent | Answer::Ambiguous => {
            response.metadata.response_code = ResponseCode::NXDomain;
        }
        // The rule should have kept this away. Refused rather than answered, so
        // the sender learns this resolver is not the one to ask — and refused
        // rather than forwarded, which is the whole point.
        Answer::NotOurs => {
            response.metadata.response_code = ResponseCode::Refused;
        }
    }

    response.to_vec().ok()
}

/// The name a query asks about, if it is a query at all.
///
/// For a platform whose one resolver receives every lookup the machine makes: it
/// has to know which name is being asked before [`crate::names::route`] can say
/// whether the question is its own. Parsing only — nothing here decides.
#[must_use]
pub fn question(query: &[u8]) -> Option<String> {
    if query.len() > limits::MAX_DNS_MESSAGE {
        return None;
    }
    let request = Message::from_vec(query).ok()?;
    if request.metadata.message_type != MessageType::Query {
        return None;
    }
    Some(request.queries.first()?.name().to_ascii())
}

/// A response saying the name does not exist, for a query about a private name.
///
/// What a platform that forwards answers for a name under the suffix of a network
/// this device holds but has switched off. Not forwarded, because that would hand
/// a public resolver the name of a private device; not answered from a roster,
/// because the network is off and nothing about it is current.
#[must_use]
pub fn non_existent(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() > limits::MAX_DNS_MESSAGE {
        return None;
    }
    let request = Message::from_vec(query).ok()?;
    if request.metadata.message_type != MessageType::Query {
        return None;
    }
    let question = request.queries.first()?.clone();
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.response_code = ResponseCode::NXDomain;
    response.add_query(question);
    response.to_vec().ok()
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use std::collections::BTreeSet;

    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    use roster::id::{DeviceId, NetworkId, OperationId};
    use roster::types::{DeviceRecord, NetworkParams, Role};

    use super::*;

    fn record(tag: u8, name: &str) -> DeviceRecord {
        DeviceRecord {
            id: DeviceId::from_bytes([tag; 32]),
            keys: Vec::new(),
            name: name.to_owned(),
            role: Role::Member,
            founder: false,
            added_by: OperationId::from_bytes([0; 32]),
            capabilities: Vec::new(),
        }
    }

    fn state() -> RosterState {
        RosterState {
            network: NetworkId::from_bytes([1; 32]),
            params: NetworkParams::new(
                vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                "example.internal",
                2_592_000,
            )
            .expect("valid"),
            devices: [record(1, "nas")].into_iter().map(|item| (item.id, item)).collect(),
            revoked: BTreeSet::new(),
        }
    }

    fn query_bytes(name: &str, kind: RecordType) -> Vec<u8> {
        let mut message = Message::query();
        message.metadata.id = 0x1234;
        message.metadata.recursion_desired = true;
        let name: Name = name.parse().expect("a valid name");
        message.add_query(Query::query(name, kind));
        message.to_vec().expect("encodes")
    }

    fn response_to(name: &str, kind: RecordType) -> Message {
        let bytes =
            respond(&state(), &Ipv4View::default(), &query_bytes(name, kind)).expect("answers");
        Message::from_vec(&bytes).expect("decodes")
    }

    #[test]
    fn a_known_name_answers_with_its_overlay_address() {
        let response = response_to("nas.example.internal.", RecordType::AAAA);

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.metadata.id, 0x1234, "the answer matches the question it answers");
        let answered = response.answers.first().expect("one answer");

        match &answered.data {
            RData::AAAA(AAAA(address)) => {
                let prefix = tunnel::Prefix::from_parameter(&state().params.ula).expect("valid");
                assert_eq!(*address, tunnel::address_of(&DeviceId::from_bytes([1; 32]), &prefix));
            }
            other => panic!("expected an AAAA record, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_name_under_the_suffix_is_denied() {
        let response = response_to("printer.example.internal.", RecordType::AAAA);
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert!(response.answers.is_empty());
    }

    /// A name outside the suffix should never arrive. Refused rather than
    /// forwarded, so a rule that is letting the wrong queries through shows up
    /// as a refusal rather than as this daemon quietly resolving the internet.
    #[test]
    fn a_name_outside_the_suffix_is_refused_not_forwarded() {
        let response = response_to("www.example.com.", RecordType::AAAA);
        assert_eq!(response.metadata.response_code, ResponseCode::Refused);
        assert!(response.answers.is_empty());
    }

    /// The name exists; this record type does not. An empty success, because
    /// saying the name does not exist is a lie a resolver may cache.
    #[test]
    fn a_known_name_with_another_record_type_is_an_empty_success() {
        let response = response_to("nas.example.internal.", RecordType::MX);

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
    }

    fn held(withheld: bool) -> Ipv4View {
        let state = state();
        let device = DeviceId::from_bytes([1; 32]);
        Ipv4View {
            holdings: std::sync::Arc::new(tunnel::Ipv4Holdings::of_state(&state)),
            withheld: std::sync::Arc::new(if withheld {
                [(device, crate::conflicts::Conflict::Gateway)].into_iter().collect()
            } else {
                std::collections::BTreeMap::new()
            }),
        }
    }

    fn answered(view: &Ipv4View, name: &str, kind: RecordType) -> Message {
        let bytes = respond(&state(), view, &query_bytes(name, kind)).expect("answers");
        Message::from_vec(&bytes).expect("decodes")
    }

    /// `A` for a device holding an IPv4 address and not withheld here.
    #[test]
    fn a_device_holding_ipv4_answers_a() {
        let view = held(false);
        let response = answered(&view, "nas.example.internal.", RecordType::A);

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        match &response.answers.first().expect("one answer").data {
            RData::A(A(address)) => {
                assert_eq!(Some(*address), view.holdings.of(&DeviceId::from_bytes([1; 32])));
            }
            other => panic!("expected an A record, got {other:?}"),
        }
    }

    /// A withheld device, or one without IPv4, answers an empty success for `A`
    /// and `AAAA` as ever.
    #[test]
    fn a_withheld_or_colliding_device_answers_an_empty_success_for_a() {
        for view in [held(true), Ipv4View::default()] {
            let response = answered(&view, "nas.example.internal.", RecordType::A);
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert!(response.answers.is_empty());

            let response = answered(&view, "nas.example.internal.", RecordType::AAAA);
            assert!(matches!(
                response.answers.first().map(|record| &record.data),
                Some(RData::AAAA(_))
            ));
        }
    }

    #[test]
    fn an_unknown_name_is_denied_for_a_too() {
        let response = answered(&held(false), "printer.example.internal.", RecordType::A);
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn the_answer_carries_the_question_back() {
        let response = response_to("nas.example.internal.", RecordType::AAAA);
        let question = response.queries.first().expect("the question is echoed");
        assert_eq!(question.name().to_ascii(), "nas.example.internal.");
        assert_eq!(question.query_type(), RecordType::AAAA);
    }

    /// A short cache, so a revoked device stops resolving on the machine roughly
    /// when it stops resolving in the roster.
    #[test]
    fn answers_are_not_cached_for_long() {
        let response = response_to("nas.example.internal.", RecordType::AAAA);
        let answered = response.answers.first().expect("one answer");
        assert!(answered.ttl <= 60, "a revocation must not be outlived by a cache entry");
    }

    /// Replying to something we could not parse means replying to whatever the
    /// sender wanted us to think it was.
    #[test]
    fn nonsense_is_not_answered() {
        for bytes in [b"".as_slice(), b"not a dns message".as_slice(), &[0u8; 3]] {
            assert!(respond(&state(), &Ipv4View::default(), bytes).is_none(), "{bytes:?}");
        }
    }

    #[test]
    fn an_oversized_message_is_refused_rather_than_parsed() {
        let too_big = vec![0u8; limits::MAX_DNS_MESSAGE.saturating_add(1)];
        assert!(respond(&state(), &Ipv4View::default(), &too_big).is_none());
    }

    /// A response is not a question. Answering one would mean two resolvers
    /// answering each other.
    #[test]
    fn a_response_is_not_answered() {
        let mut message = Message::response(1, OpCode::Query);
        message.add_query(Query::query(
            "nas.example.internal.".parse().expect("valid"),
            RecordType::AAAA,
        ));
        let bytes = message.to_vec().expect("encodes");

        assert!(respond(&state(), &Ipv4View::default(), &bytes).is_none());
    }

    #[test]
    fn a_query_with_no_question_is_not_answered() {
        let bytes = Message::query().to_vec().expect("encodes");
        assert!(respond(&state(), &Ipv4View::default(), &bytes).is_none());
    }

    /// A removed device stops resolving on the wire too, not only in `names`.
    #[test]
    fn a_removed_device_stops_answering() {
        let mut state = state();
        state.devices.clear();

        let bytes = respond(
            &state,
            &Ipv4View::default(),
            &query_bytes("nas.example.internal.", RecordType::AAAA),
        )
        .expect("answers");
        let response = Message::from_vec(&bytes).expect("decodes");

        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }

    /// Nothing in this module resolves anything itself.
    #[test]
    fn there_is_no_client_here() {
        let code = crate::code_of(include_str!("wire.rs"));
        for forbidden in ["Resolver::new", "lookup(", "UdpClientStream", "connect("] {
            assert!(!code.contains(forbidden), "`{forbidden}` would make this a forwarder");
        }
    }

    #[test]
    fn the_answer_is_authoritative() {
        let response = response_to("nas.example.internal.", RecordType::AAAA);
        assert!(
            response.metadata.authoritative,
            "this daemon is the whole truth about its suffix; saying otherwise invites a \
             resolver to look elsewhere"
        );
    }

    #[test]
    fn the_question_is_read_and_nothing_else_is_decided() {
        let bytes = query_bytes("nas.example.internal.", RecordType::AAAA);
        assert_eq!(question(&bytes).as_deref(), Some("nas.example.internal."));
        assert_eq!(question(b"not a message"), None);
    }

    #[test]
    fn a_private_name_is_answered_as_non_existent() {
        let bytes = non_existent(&query_bytes("laptop.work.internal.", RecordType::AAAA)).unwrap();
        let response = Message::from_vec(&bytes).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(response.metadata.id, 0x1234);
        assert!(response.answers.is_empty());
    }
}

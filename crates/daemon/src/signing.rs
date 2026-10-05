//! Acts waiting for a signature this process cannot make.
//!
//! Some devices hold their signing key where this process can reach it, and an
//! administrative act is one call. Others do not: a phone's key is in the
//! keystore behind the lock, and a desktop's may be in the machine's key store
//! behind the person. On those, an act stops in the middle — everything is
//! prepared, and the one thing left is a signature that only somebody else can
//! produce.
//!
//! This is where the middle is kept.
//!
//! # It is portable, and that is the point
//!
//! Nothing here knows what a key store is. The rule it enforces — *what was
//! prepared is what gets signed, once, and not forever* — is the same rule on
//! every platform that has to ask somebody. Windows is the first to need it;
//! Linux and macOS will need the same one, and this is what they will reuse.
//!
//! # Three rules, and why each one
//!
//! **Bound to its act.** The request is handed back with the answer, so the
//! signature is verified against the message that was prepared and no other. A
//! signature obtained for one act cannot complete a different one, because it
//! will not verify against the bytes that act committed to. The binding is the
//! cryptography's, not a comparison somebody remembered to write.
//!
//! **Single use.** Answering takes the request out. A replayed answer finds
//! nothing to complete, so an act cannot be made to happen twice from one
//! signature — which matters most for the acts that cannot be withdrawn, since
//! the log is append-only.
//!
//! **It expires.** A person who walks away from a prompt leaves an act half
//! finished. Without a limit it would sit there until the daemon stopped,
//! completable by whatever connected next; with one it stops being completable
//! while the person is still at their desk deciding they did not mean it.

use std::collections::HashMap;

use identity::detached::SigningRequest;

/// How long a prepared act waits for its signature.
///
/// Long enough for a person to read a prompt, find the reader or put a finger on
/// it, and decide — and short enough that walking away ends the act rather than
/// leaving it open. Five minutes is the first of those and not much of the
/// second.
pub const WAITS_FOR: u64 = 5 * 60 * 1_000;

/// Where a network's roster stood when a batch was prepared over it.
///
/// A batch is built over the roster as it is: its operations name the heads as
/// parents, and its snapshot is numbered after the one held. If either moves
/// while a person is deciding — another admin's operation arrives, or their
/// snapshot does — what was authorised is no longer what it would do. So this is
/// taken when the batch is prepared, compared when its signatures arrive, and a
/// batch whose moment has passed is not applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moment {
    /// The roster's heads.
    pub heads: Vec<roster::id::OperationId>,
    /// The sequence of the snapshot it holds, if any.
    pub snapshot: Option<u64>,
}

/// Why a signature could not be matched to anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unmatched {
    /// No act is waiting under that id.
    ///
    /// Either it was never issued, or it has already been answered — which are
    /// the same thing to a caller, and deliberately: saying which would tell
    /// whoever asked whether they had guessed a real id.
    Unknown,
    /// An act was waiting under that id and waited too long.
    Expired,
    /// The answer did not carry one signature for each thing the act prepared.
    ///
    /// The act is gone all the same: a batch is answered once, whole, and an
    /// answer that is not whole is not a first attempt to be followed by a
    /// second.
    Count {
        /// How many the act was waiting for.
        wanted: usize,
        /// How many the answer carried.
        given: usize,
    },
}

impl core::fmt::Display for Unmatched {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unknown => f.write_str(
                "no act is waiting for that signature. It may have been completed already, or \
                 abandoned",
            ),
            Self::Expired => f.write_str(
                "the act waited too long for a signature and was dropped. Nothing was signed; \
                 ask for it again",
            ),
            Self::Count { wanted, given } => write!(
                f,
                "the act was waiting for {wanted} signature{} and the answer carried {given}. \
                 Nothing was applied; ask for it again",
                if *wanted == 1 { "" } else { "s" },
            ),
        }
    }
}

/// One act, prepared and waiting.
struct Held<T> {
    /// The bytes that were prepared, which are the bytes that may be signed —
    /// every signature the act needs, in the order they take effect. One
    /// batch, answered once and whole.
    requests: Vec<SigningRequest>,
    /// What the caller means to do once it has the signature.
    act: T,
    /// When it was issued, in milliseconds.
    issued: u64,
    /// Who asked for it.
    ///
    /// **Because the id is not a secret.** It is the issuing time and a counter,
    /// so anybody who can reach this daemon can write one down — and while
    /// completing somebody else's act still needs a signature they cannot
    /// produce, *abandoning* it needs only the id. Without this, one person on a
    /// machine could end another's half-finished act by guessing.
    by: crate::control::Caller,
}

/// The acts this daemon has prepared and not finished.
///
/// `T` is whatever the caller needs to resume — this type never looks at it.
pub struct Waiting<T> {
    /// By id.
    held: HashMap<String, Held<T>>,
    /// What the next id will be, so two acts prepared in the same millisecond
    /// cannot collide.
    next: u64,
    /// Acts that ended without an answer — expired — and have not been handed
    /// back yet.
    ///
    /// Kept rather than dropped because ending is not always free: a founding
    /// that stops at its signature has already made a directory and an identity,
    /// and an act nobody answered must leave nothing behind. The caller collects
    /// them with [`Self::lapsed`] and tidies after each.
    lapsed: Vec<T>,
}

impl<T> Default for Waiting<T> {
    fn default() -> Self {
        Self { held: HashMap::new(), next: 0, lapsed: Vec::new() }
    }
}

impl<T> Waiting<T> {
    /// Holds a prepared act, and returns the id the answer must carry.
    ///
    /// Issuing also drops anything that has expired, so a daemon left running
    /// does not accumulate acts nobody ever signed.
    ///
    /// **Who asked is not optional.** A defaulted one would be
    /// [`Caller::Unattributed`][crate::control::Caller::Unattributed], which
    /// matches a network with no owner and therefore matches anybody — so a call
    /// site that forgot would be a call site that let everybody in, silently.
    pub fn issue_for(
        &mut self,
        requests: Vec<SigningRequest>,
        act: T,
        now: u64,
        by: crate::control::Caller,
    ) -> String {
        self.forget_expired(now);
        self.next = self.next.wrapping_add(1);
        let id = format!("{now:x}-{:x}", self.next);
        self.held.insert(id.clone(), Held { requests, act, issued: now, by });
        id
    }

    /// Who asked for the act waiting under `id`, if one is.
    ///
    /// `None` where nothing is waiting, which reads the same for an id that was
    /// never issued and one already answered — the distinction [`answer`] also
    /// refuses to draw, and for the same reason.
    ///
    /// [`answer`]: Self::answer
    #[must_use]
    pub fn asked_by(&self, id: &str) -> Option<&crate::control::Caller> {
        self.held.get(id).map(|held| &held.by)
    }

    /// Takes the act waiting under `id`, with the requests it was prepared from,
    /// for an answer carrying `given` signatures.
    ///
    /// Taking it out is what makes an answer single use — including an answer
    /// that is refused: a batch whose answer came back short is over, not
    /// waiting for the rest.
    ///
    /// # Errors
    ///
    /// When nothing is waiting under that id, what was waiting has expired, or
    /// the answer does not carry one signature per request.
    pub fn answer(
        &mut self,
        id: &str,
        given: usize,
        now: u64,
    ) -> Result<(Vec<SigningRequest>, T), Unmatched> {
        let held = self.held.remove(id).ok_or(Unmatched::Unknown)?;
        if now.saturating_sub(held.issued) > WAITS_FOR {
            self.lapsed.push(held.act);
            return Err(Unmatched::Expired);
        }
        if held.requests.len() != given {
            return Err(Unmatched::Count { wanted: held.requests.len(), given });
        }
        Ok((held.requests, held.act))
    }

    /// Ends the act waiting under `id` without completing it, and hands it back
    /// so whatever it had prepared can be tidied away.
    ///
    /// What a person declining reaches: the act is over, and saying so at once
    /// is better than leaving it to expire.
    pub fn abandon(&mut self, id: &str) -> Option<T> {
        self.held.remove(id).map(|held| held.act)
    }

    /// The acts that expired since this was last asked, for tidying after.
    pub fn lapsed(&mut self) -> Vec<T> {
        core::mem::take(&mut self.lapsed)
    }

    /// How many acts are waiting. For the report, and for tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether nothing is waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Ends everything that has waited too long, keeping each act for
    /// [`Self::lapsed`].
    fn forget_expired(&mut self, now: u64) {
        let expired: Vec<String> = self
            .held
            .iter()
            .filter(|(_, held)| now.saturating_sub(held.issued) > WAITS_FOR)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            if let Some(held) = self.held.remove(&id) {
                self.lapsed.push(held.act);
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use identity::NodeIdentity;
    use identity::detached::prepare_operation;
    use roster::types::{NetworkParams, OperationBody, OperationCore, Role};

    use super::*;

    /// A prepared operation, of whatever kind; what matters here is that two of
    /// them differ.
    fn request(identity: &NodeIdentity, name: &str) -> SigningRequest {
        let core = OperationCore::new(
            1_735_689_600_000,
            identity.signing_key().algorithm(),
            OperationBody::CreateNetwork {
                device: identity.device_spec(name, Role::Admin, true, vec![]).unwrap(),
                params: NetworkParams::new(
                    vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
                    "example.internal",
                    2_592_000,
                )
                .unwrap(),
            },
            vec![],
            identity.signing_key().key_id(),
            roster::id::NetworkId::from_bytes([0; 32]),
        )
        .unwrap();
        prepare_operation(&core, &identity.signing_key().public_key())
    }

    /// A batch of one, which is what most of these tests need.
    fn one(identity: &NodeIdentity, name: &str) -> Vec<SigningRequest> {
        vec![request(identity, name)]
    }

    /// **A batch is answered whole.** An answer carrying the wrong number of
    /// signatures is refused, and the act is over rather than waiting for the
    /// rest — an answer is single use whether or not it was any good.
    #[test]
    fn a_batch_answered_short_is_refused_and_gone() {
        let identity = NodeIdentity::generate().unwrap();
        let mut waiting = Waiting::default();

        let id = waiting.issue_for(
            vec![request(&identity, "laptop"), request(&identity, "phone")],
            "replace laptop",
            1_000,
            crate::control::Caller::Unattributed,
        );
        let refusal = waiting.answer(&id, 1, 1_000).map(|_| ()).expect_err("short");
        assert_eq!(Unmatched::Count { wanted: 2, given: 1 }, refusal);
        assert!(refusal.to_string().contains("Nothing was applied"), "{refusal}");
        assert_eq!(
            Err(Unmatched::Unknown),
            waiting.answer(&id, 2, 1_000).map(|_| ()),
            "and the whole answer cannot follow the short one"
        );
    }

    /// The requests come back as they were prepared, in order.
    #[test]
    fn a_batch_comes_back_in_its_order() {
        let identity = NodeIdentity::generate().unwrap();
        let mut waiting = Waiting::default();

        let id = waiting.issue_for(
            vec![request(&identity, "laptop"), request(&identity, "phone")],
            "replace",
            1_000,
            crate::control::Caller::Unattributed,
        );
        let (back, _) = waiting.answer(&id, 2, 1_000).expect("whole");
        assert_eq!(request(&identity, "laptop").message(), back.first().unwrap().message());
        assert_eq!(request(&identity, "phone").message(), back.get(1).unwrap().message());
    }

    /// **A waiting act remembers who asked for it.**
    ///
    /// Found by removing the rule: making `asked_by` answer *nobody* broke
    /// nothing, and *nobody* is the caller that matches every unowned thing on
    /// the machine. The id is the issuing time and a counter, so anybody who can
    /// reach the daemon can write one down — and abandoning somebody else's act
    /// needs only the id, no signature at all.
    #[test]
    fn who_asked_for_an_act_is_who_it_says() {
        let identity = NodeIdentity::generate().unwrap();
        let mut waiting: Waiting<&str> = Waiting::default();
        let alice = crate::control::Caller::Identified {
            name: "S-1-5-21-alice".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };
        let bob = crate::control::Caller::Identified {
            name: "S-1-5-21-bob".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };

        let id = waiting.issue_for(one(&identity, "laptop"), "revoke", 1_000, alice.clone());

        assert_eq!(Some(&alice), waiting.asked_by(&id), "hers, by name");
        assert_ne!(Some(&bob), waiting.asked_by(&id), "and not his");
        assert_ne!(
            Some(&crate::control::Caller::Unattributed),
            waiting.asked_by(&id),
            "and not nobody's, which would match every unowned thing on the machine"
        );

        assert_eq!(None, waiting.asked_by("18f3a-9"), "an id nothing is waiting under says nobody");
    }

    #[test]
    fn an_answer_brings_back_the_act_that_was_prepared() {
        let identity = NodeIdentity::generate().unwrap();
        let mut waiting = Waiting::default();

        let id = waiting.issue_for(
            one(&identity, "laptop"),
            "revoke laptop",
            1_000,
            crate::control::Caller::Unattributed,
        );
        let (back, act) = waiting.answer(&id, 1, 2_000).expect("it was waiting");

        assert_eq!("revoke laptop", act, "the act comes back, not a fresh one");
        assert_eq!(
            request(&identity, "laptop").message(),
            back.first().unwrap().message(),
            "so do its bytes"
        );
    }

    /// The rule that matters most, because the log is append-only: one signature
    /// completes one act.
    #[test]
    fn an_answer_is_good_once() {
        let identity = NodeIdentity::generate().unwrap();
        let mut waiting = Waiting::default();

        let id = waiting.issue_for(
            one(&identity, "laptop"),
            "admit laptop",
            1_000,
            crate::control::Caller::Unattributed,
        );
        waiting.answer(&id, 1, 1_000).expect("the first time");
        assert_eq!(
            Err(Unmatched::Unknown),
            waiting.answer(&id, 1, 1_000).map(|_| ()),
            "and not the second — an act that cannot be withdrawn must not happen twice"
        );
    }

    #[test]
    fn an_id_nobody_issued_matches_nothing() {
        let mut waiting: Waiting<&str> = Waiting::default();
        assert_eq!(Err(Unmatched::Unknown), waiting.answer("beef-1", 1, 1_000).map(|_| ()));
    }

    /// An id that was never issued and one that has been used answer the same
    /// way, so guessing tells nobody they guessed right.
    #[test]
    fn a_used_id_and_an_invented_one_answer_alike() {
        let identity = NodeIdentity::generate().unwrap();
        let mut waiting = Waiting::default();

        let id = waiting.issue_for(
            one(&identity, "laptop"),
            "admit",
            1_000,
            crate::control::Caller::Unattributed,
        );
        waiting.answer(&id, 1, 1_000).expect("used");

        let used = waiting.answer(&id, 1, 1_000).map(|_| ()).expect_err("gone");
        let invented = waiting.answer("nothing-like-it", 1, 1_000).map(|_| ()).expect_err("gone");
        assert_eq!(used, invented, "the same answer, so neither reveals which it was");
    }

    #[test]
    fn an_act_nobody_signed_expires_and_says_so() {
        let identity = NodeIdentity::generate().unwrap();
        let mut waiting = Waiting::default();

        let id = waiting.issue_for(
            one(&identity, "laptop"),
            "revoke",
            1_000,
            crate::control::Caller::Unattributed,
        );
        let refusal = waiting.answer(&id, 1, 1_000 + WAITS_FOR + 1).expect_err("too late");
        assert_eq!(Unmatched::Expired, refusal);
        assert!(refusal.to_string().contains("Nothing was signed"), "and says nothing happened");
    }

    #[test]
    fn an_act_signed_at_the_last_moment_still_completes() {
        let identity = NodeIdentity::generate().unwrap();
        let mut waiting = Waiting::default();

        let id = waiting.issue_for(
            one(&identity, "laptop"),
            "revoke",
            1_000,
            crate::control::Caller::Unattributed,
        );
        assert!(waiting.answer(&id, 1, 1_000 + WAITS_FOR).is_ok(), "the boundary is not past it");
    }

    /// A daemon left running for weeks must not be holding every act somebody
    /// started and walked away from.
    #[test]
    fn preparing_another_act_clears_out_the_abandoned_ones() {
        let identity = NodeIdentity::generate().unwrap();
        let mut waiting = Waiting::default();

        for _ in 0..5 {
            waiting.issue_for(
                one(&identity, "laptop"),
                "admit",
                1_000,
                crate::control::Caller::Unattributed,
            );
        }
        assert_eq!(5, waiting.len());

        waiting.issue_for(
            one(&identity, "laptop"),
            "admit",
            1_000 + WAITS_FOR + 1,
            crate::control::Caller::Unattributed,
        );
        assert_eq!(1, waiting.len(), "only the new one is left");
        assert_eq!(5, waiting.lapsed().len(), "and the five that expired are handed back");
        assert!(waiting.lapsed().is_empty(), "once");
    }

    /// An act that expires while being answered is handed back too, and so is
    /// one a person declines — each may have left something to tidy away.
    #[test]
    fn an_act_that_ends_unanswered_is_handed_back() {
        let identity = NodeIdentity::generate().unwrap();
        let mut waiting = Waiting::default();

        let late = waiting.issue_for(
            one(&identity, "laptop"),
            "found casa",
            1_000,
            crate::control::Caller::Unattributed,
        );
        let _expired = waiting.answer(&late, 1, 1_000 + WAITS_FOR + 1);
        assert_eq!(vec!["found casa"], waiting.lapsed());

        let declined = waiting.issue_for(
            one(&identity, "phone"),
            "found ufficio",
            1_000,
            crate::control::Caller::Unattributed,
        );
        assert_eq!(Some("found ufficio"), waiting.abandon(&declined));
        assert_eq!(None, waiting.abandon(&declined), "once");
    }

    /// Two acts prepared in the same millisecond are two acts, and answering one
    /// must not complete the other.
    #[test]
    fn two_acts_at_once_stay_apart() {
        let identity = NodeIdentity::generate().unwrap();
        let mut waiting = Waiting::default();

        let first = waiting.issue_for(
            one(&identity, "laptop"),
            "revoke laptop",
            1_000,
            crate::control::Caller::Unattributed,
        );
        let second = waiting.issue_for(
            one(&identity, "phone"),
            "revoke phone",
            1_000,
            crate::control::Caller::Unattributed,
        );
        assert_ne!(first, second, "the same millisecond is not the same act");

        let (_, act) = waiting.answer(&second, 1, 1_000).unwrap();
        assert_eq!("revoke phone", act);
        let (_, act) = waiting.answer(&first, 1, 1_000).unwrap();
        assert_eq!("revoke laptop", act, "answering one left the other alone");
    }

    #[test]
    fn abandoning_ends_the_act() {
        let identity = NodeIdentity::generate().unwrap();
        let mut waiting = Waiting::default();

        let id = waiting.issue_for(
            one(&identity, "laptop"),
            "revoke",
            1_000,
            crate::control::Caller::Unattributed,
        );
        waiting.abandon(&id);
        assert!(waiting.is_empty(), "nothing is left holding a half-finished act");
        assert_eq!(Err(Unmatched::Unknown), waiting.answer(&id, 1, 1_000).map(|_| ()));
    }
}

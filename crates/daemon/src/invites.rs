//! The invites an admin's device has issued, what each is for, and the request
//! each brought.
//!
//! An invite carries only the relay, the network id and a secret. Who it is
//! for — the name, role, mode and groups the device will be admitted with — is
//! kept here, on the inviting device, with when it ends, the request that
//! arrived through it and what a person decided about that request. None of it
//! enters the roster: it is this device's promise to itself about one door it
//! opened.
//!
//! # One request, then a person
//!
//! An invite takes one request, before its expiry, unless withdrawn. The
//! request is kept here, **asking nobody**, until a person approves or rejects
//! it — which may be days later: the expiry bounds only how long a request may
//! take to arrive. An approved request is delivered when its device answers,
//! and the invite is used once it has the network.
//!
//! The expiry is measured on this device's clock, the only one that matters for
//! a door this device keeps. The file is covered by the network's checkpoint, so
//! a request written here by anything but the daemon is not believed.

use std::path::{Path, PathBuf};

use enrollment::Invite;
use roster::leaf::{Group, Mode};
use roster::sign::PublicKey;
use roster::types::{Algorithm, Role};
use serde::{Deserialize, Serialize};

use crate::admitting::Applicant;
use crate::error::{Error, Result};

/// The file the record is kept in, beside the network's log.
pub const FILE_NAME: &str = "invites.json";

/// How long an invite stays open unless the admin says otherwise: a day.
pub const DEFAULT_LIFETIME_SECS: u64 = 24 * 60 * 60;

/// The longest an invite may stay open: a week. A door left open longer is a
/// door nobody remembers opening.
pub const LONGEST_LIFETIME_SECS: u64 = 7 * 24 * 60 * 60;

/// How long an ended invite is kept, so the list can still say what became of
/// it.
pub const KEPT_AFTER_ENDING_SECS: u64 = 24 * 60 * 60;

/// Who an invite is for: what the device it admits will be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invited {
    /// The name it is admitted under.
    pub name: String,
    /// Admin or member.
    pub role: Role,
    /// Full or light. An admin is always full.
    pub mode: Mode,
    /// The groups it joins.
    pub groups: Vec<Group>,
    /// The IPv4 address it is assigned, where the admin chose one.
    pub ipv4: Option<[u8; 4]>,
}

/// What a person decided about a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Nobody has yet.
    Waiting,
    /// Approved at this second: the admission is signed and in the roster.
    Approved {
        /// When.
        at: u64,
        /// Whether the device has been given the network.
        delivered: bool,
    },
    /// Rejected at this second. Nothing was signed.
    Rejected {
        /// When.
        at: u64,
    },
}

/// The request a device made through an invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The device: its keys, proved when the request was taken, and the name it
    /// proposes.
    pub applicant: Applicant,
    /// When it arrived, in seconds since the epoch on this device's clock.
    pub arrived_at: u64,
    /// What a person made of it.
    pub decision: Decision,
}

impl Request {
    /// The device's signing key, in the shape a person compares.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        crate::joining::fingerprint(&self.applicant.signing)
    }
}

/// One invite and what it is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The invite, secret included.
    pub invite: Invite,
    /// Who it is for.
    pub invited: Invited,
    /// When it stops taking a request, in seconds since the epoch on this
    /// device's clock.
    pub expires_at: u64,
    /// The request that arrived through it, if one has.
    pub request: Option<Request>,
    /// Whether the admin withdrew it.
    pub withdrawn: bool,
}

/// Where an invite stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Waiting for its device's request: dialled.
    Open,
    /// A request arrived, and waits for a person.
    Requested,
    /// Approved, and its device not yet given the network.
    Approved,
    /// Its device was given the network.
    Used,
    /// Its request was rejected.
    Rejected,
    /// It ended at its expiry with no request.
    Expired,
    /// The admin withdrew it.
    Withdrawn,
}

impl Standing {
    /// The word a list shows.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Requested => "requested",
            Self::Approved => "approved",
            Self::Used => "used",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Withdrawn => "withdrawn",
        }
    }

    /// Whether nothing more will happen to it.
    #[must_use]
    pub const fn ended(self) -> bool {
        matches!(self, Self::Used | Self::Rejected | Self::Expired | Self::Withdrawn)
    }
}

impl Record {
    /// A new invite into `network` at `relay`, for `invited`, open from `now`
    /// for `lifetime` seconds.
    ///
    /// # Errors
    ///
    /// When no invite can be made, or `invited` asks for a light admin.
    pub fn issue(
        relay: &str,
        network: roster::id::NetworkId,
        invited: Invited,
        now: u64,
        lifetime: u64,
    ) -> Result<Self> {
        if invited.role == Role::Admin && invited.mode == Mode::Light {
            return Err(Error::Refused {
                cause: "an admin is a full member: it cannot be invited light".to_owned(),
            });
        }
        let invite = Invite::issue(relay, network)
            .map_err(|cause| Error::Refused { cause: cause.to_string() })?;
        Ok(Self {
            invite,
            invited,
            expires_at: now.saturating_add(lifetime),
            request: None,
            withdrawn: false,
        })
    }

    /// Where it stands at `now`. A request that arrived is past the expiry's
    /// reach: the expiry bounds only its arrival.
    #[must_use]
    pub const fn standing(&self, now: u64) -> Standing {
        if self.withdrawn {
            return Standing::Withdrawn;
        }
        match &self.request {
            Some(Request { decision: Decision::Waiting, .. }) => Standing::Requested,
            Some(Request { decision: Decision::Approved { delivered: false, .. }, .. }) => {
                Standing::Approved
            }
            Some(Request { decision: Decision::Approved { delivered: true, .. }, .. }) => {
                Standing::Used
            }
            Some(Request { decision: Decision::Rejected { .. }, .. }) => Standing::Rejected,
            None if now >= self.expires_at => Standing::Expired,
            None => Standing::Open,
        }
    }

    /// When nothing more happened to it, for an ended one.
    const fn ended_at(&self) -> u64 {
        match &self.request {
            Some(Request {
                decision: Decision::Approved { at, .. } | Decision::Rejected { at },
                ..
            }) => {
                if *at > self.expires_at {
                    *at
                } else {
                    self.expires_at
                }
            }
            _ => self.expires_at,
        }
    }
}

/// The invites, as kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Invites {
    records: Vec<Record>,
}

impl Invites {
    /// Every invite, in the order issued.
    #[must_use]
    pub fn all(&self) -> &[Record] {
        &self.records
    }

    /// The invites still waiting for a request at `now`: the ones whose
    /// rendezvous is dialled.
    pub fn open(&self, now: u64) -> impl Iterator<Item = &Record> {
        self.records.iter().filter(move |record| record.standing(now) == Standing::Open)
    }

    /// The approved invites whose device does not have the network yet: the
    /// ones whose device is dialled to deliver it.
    pub fn delivering(&self, now: u64) -> impl Iterator<Item = &Record> {
        self.records.iter().filter(move |record| record.standing(now) == Standing::Approved)
    }

    /// Keeps a new invite.
    pub fn add(&mut self, record: Record) {
        self.records.push(record);
    }

    /// Keeps the request that arrived through the invite with `secret`.
    ///
    /// Whether it was kept: only an open invite takes one, and only one.
    pub fn arrived(
        &mut self,
        secret: &[u8; enrollment::invite::SECRET_LEN],
        applicant: Applicant,
        now: u64,
    ) -> bool {
        let Some(record) = self.with_secret(secret) else { return false };
        if record.standing(now) != Standing::Open {
            return false;
        }
        record.request = Some(Request { applicant, arrived_at: now, decision: Decision::Waiting });
        true
    }

    /// The invite for the device to be called `name` that stands as `standing`,
    /// if there is one.
    #[must_use]
    pub fn named(&self, name: &str, standing: Standing, now: u64) -> Option<&Record> {
        self.records
            .iter()
            .find(|record| record.invited.name == name && record.standing(now) == standing)
    }

    /// The invite for the device to be called `name` that has not ended: open,
    /// requested or approved.
    #[must_use]
    pub fn live_named(&self, name: &str, now: u64) -> Option<&Record> {
        self.records
            .iter()
            .find(|record| record.invited.name == name && !record.standing(now).ended())
    }

    /// Approves the request waiting on the invite with `secret`. Whether there
    /// was one.
    pub fn approve(&mut self, secret: &[u8; enrollment::invite::SECRET_LEN], now: u64) -> bool {
        self.decide(secret, now, Decision::Approved { at: now, delivered: false })
    }

    /// Rejects the request waiting on the invite with `secret`. Whether there
    /// was one.
    pub fn reject(&mut self, secret: &[u8; enrollment::invite::SECRET_LEN], now: u64) -> bool {
        self.decide(secret, now, Decision::Rejected { at: now })
    }

    fn decide(
        &mut self,
        secret: &[u8; enrollment::invite::SECRET_LEN],
        now: u64,
        decision: Decision,
    ) -> bool {
        let Some(record) = self.with_secret(secret) else { return false };
        if record.standing(now) != Standing::Requested {
            return false;
        }
        if let Some(request) = record.request.as_mut() {
            request.decision = decision;
        }
        true
    }

    /// Records that the device approved through the invite with `secret` has
    /// the network. Whether anything changed.
    pub fn delivered(&mut self, secret: &[u8; enrollment::invite::SECRET_LEN]) -> bool {
        let Some(record) = self.with_secret(secret) else { return false };
        match record.request.as_mut() {
            Some(Request { decision: Decision::Approved { delivered, .. }, .. }) if !*delivered => {
                *delivered = true;
                true
            }
            _ => false,
        }
    }

    /// Withdraws the invite with `secret`, while nothing has been signed
    /// through it: open, or with a request waiting. Whether it was withdrawn.
    pub fn withdraw(&mut self, secret: &[u8; enrollment::invite::SECRET_LEN], now: u64) -> bool {
        let Some(record) = self.with_secret(secret) else { return false };
        if !matches!(record.standing(now), Standing::Open | Standing::Requested) {
            return false;
        }
        record.withdrawn = true;
        true
    }

    /// Forgets invites that ended more than a day ago, so the record does not
    /// grow without end. One still waiting on anything is kept however old.
    pub fn forget_ended(&mut self, now: u64) {
        self.records.retain(|record| {
            !record.standing(now).ended()
                || now < record.ended_at().saturating_add(KEPT_AFTER_ENDING_SECS)
        });
    }

    fn with_secret(
        &mut self,
        secret: &[u8; enrollment::invite::SECRET_LEN],
    ) -> Option<&mut Record> {
        self.records.iter_mut().find(|record| record.invite.secret == *secret)
    }
}

/// An invite as the file keeps it.
#[derive(Debug, Serialize, Deserialize)]
struct Kept {
    invite: String,
    name: String,
    role: String,
    mode: String,
    groups: Vec<String>,
    /// Written only where one was chosen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ipv4: Option<String>,
    expires_at: u64,
    /// Written only once one arrived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request: Option<KeptRequest>,
    withdrawn: bool,
}

/// A request as the file keeps it.
#[derive(Debug, Serialize, Deserialize)]
struct KeptRequest {
    algorithm: String,
    signing: String,
    transport: String,
    attestation: String,
    name: String,
    arrived_at: u64,
    /// `waiting`, `approved` or `rejected`.
    decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decided_at: Option<u64>,
    #[serde(default)]
    delivered: bool,
}

impl KeptRequest {
    fn of(request: &Request) -> Self {
        let (decision, decided_at, delivered) = match request.decision {
            Decision::Waiting => ("waiting", None, false),
            Decision::Approved { at, delivered } => ("approved", Some(at), delivered),
            Decision::Rejected { at } => ("rejected", Some(at), false),
        };
        let applicant = &request.applicant;
        Self {
            algorithm: applicant.signing.algorithm().as_str().to_owned(),
            signing: roster::hex::encode(applicant.signing.as_bytes()),
            transport: roster::hex::encode(applicant.transport.as_bytes()),
            attestation: roster::hex::encode(applicant.attestation.as_bytes()),
            name: applicant.name.clone(),
            arrived_at: request.arrived_at,
            decision: decision.to_owned(),
            decided_at,
            delivered,
        }
    }

    fn read(self) -> core::result::Result<Request, &'static str> {
        let key = |algorithm: Algorithm, text: &str| {
            roster::hex::decode(text)
                .and_then(|bytes| PublicKey::new(algorithm, bytes).ok())
                .ok_or("a request whose keys do not read")
        };
        let algorithm = Algorithm::parse(&self.algorithm)
            .map_err(|_| "a request whose algorithm is unknown")?;
        let applicant = Applicant {
            signing: key(algorithm, &self.signing)?,
            transport: key(Algorithm::Ed25519, &self.transport)?,
            attestation: key(Algorithm::Ed25519, &self.attestation)?,
            name: self.name,
        };
        let decision = match (self.decision.as_str(), self.decided_at) {
            ("waiting", _) => Decision::Waiting,
            ("approved", Some(at)) => Decision::Approved { at, delivered: self.delivered },
            ("rejected", Some(at)) => Decision::Rejected { at },
            _ => return Err("a request whose decision does not read"),
        };
        Ok(Request { applicant, arrived_at: self.arrived_at, decision })
    }
}

/// The record on disk, beside a network's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteFile {
    path: PathBuf,
}

impl InviteFile {
    /// The record kept in a network's directory.
    #[must_use]
    pub fn beside(log: &Path) -> Self {
        let directory = log.parent().unwrap_or_else(|| Path::new("."));
        Self { path: directory.join(FILE_NAME) }
    }

    /// Reads the invites. A missing file is none.
    ///
    /// # Errors
    ///
    /// When the file exists and cannot be read, or holds something that is not
    /// a record of invites.
    pub fn load(&self) -> Result<Invites> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Invites::default());
            }
            Err(cause) => return Err(self.failure(&cause.to_string())),
        };
        let kept: Vec<Kept> =
            serde_json::from_slice(&bytes).map_err(|cause| self.failure(&cause.to_string()))?;
        let mut records = Vec::with_capacity(kept.len());
        for one in kept {
            let invite =
                Invite::from_text(&one.invite).map_err(|cause| self.failure(&cause.to_string()))?;
            let role = match one.role.as_str() {
                "admin" => Role::Admin,
                "member" => Role::Member,
                _ => return Err(self.failure("a role that is neither admin nor member")),
            };
            let mode = Mode::parse(&one.mode).map_err(|cause| self.failure(&cause.to_string()))?;
            let groups = one
                .groups
                .iter()
                .map(Group::new)
                .collect::<roster::Result<Vec<_>>>()
                .map_err(|cause| self.failure(&cause.to_string()))?;
            let ipv4 = match one.ipv4.as_deref().map(str::parse::<std::net::Ipv4Addr>) {
                None => None,
                Some(Ok(address)) => Some(address.octets()),
                Some(Err(_)) => return Err(self.failure("an IPv4 address that does not read")),
            };
            let request = one
                .request
                .map(KeptRequest::read)
                .transpose()
                .map_err(|cause| self.failure(cause))?;
            records.push(Record {
                invite,
                invited: Invited { name: one.name, role, mode, groups, ipv4 },
                expires_at: one.expires_at,
                request,
                withdrawn: one.withdrawn,
            });
        }
        Ok(Invites { records })
    }

    /// Writes the invites, whole, in place of what was kept.
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub fn save(&self, invites: &Invites) -> Result<()> {
        self.write(&self.encode(invites)?)
    }

    /// Writes bytes [`Self::encode`] made, in place of what was kept.
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub fn write(&self, encoded: &[u8]) -> Result<()> {
        crate::state::replace_file(&self.path, encoded)
    }

    /// The invites as the file keeps them.
    ///
    /// # Errors
    ///
    /// When they cannot be encoded.
    pub fn encode(&self, invites: &Invites) -> Result<Vec<u8>> {
        let kept: Vec<Kept> = invites
            .records
            .iter()
            .map(|record| Kept {
                invite: record.invite.to_text(),
                name: record.invited.name.clone(),
                role: match record.invited.role {
                    Role::Admin => "admin",
                    Role::Member => "member",
                }
                .to_owned(),
                mode: record.invited.mode.as_str().to_owned(),
                groups: record
                    .invited
                    .groups
                    .iter()
                    .map(|group| group.as_str().to_owned())
                    .collect(),
                ipv4: record
                    .invited
                    .ipv4
                    .map(|octets| std::net::Ipv4Addr::from(octets).to_string()),
                expires_at: record.expires_at,
                request: record.request.as_ref().map(KeptRequest::of),
                withdrawn: record.withdrawn,
            })
            .collect();
        serde_json::to_vec_pretty(&kept).map_err(|cause| self.failure(&cause.to_string()))
    }

    fn failure(&self, cause: &str) -> Error {
        Error::State { path: self.path.clone(), cause: cause.to_owned() }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn invited() -> Invited {
        Invited {
            name: "sensor".to_owned(),
            role: Role::Member,
            mode: Mode::Light,
            groups: vec![Group::new("sensori").unwrap()],
            ipv4: Some([100, 64, 0, 9]),
        }
    }

    fn record() -> Record {
        Record::issue(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a@relay.example:4433",
            roster::id::NetworkId::from_bytes([7; 32]),
            invited(),
            NOW,
            DEFAULT_LIFETIME_SECS,
        )
        .unwrap()
    }

    fn applicant(name: &str) -> Applicant {
        let device = identity::NodeIdentity::generate().unwrap();
        Applicant {
            signing: device.signing_key().public_key(),
            transport: device.transport_key().public_key(),
            attestation: device.attestation_key().public_key(),
            name: name.to_owned(),
        }
    }

    #[test]
    fn an_open_invite_takes_one_request_and_is_dialled_no_more() {
        let record = record();
        let secret = record.invite.secret;
        let mut invites = Invites::default();
        invites.add(record);
        assert_eq!(invites.open(NOW).count(), 1);
        assert!(invites.arrived(&secret, applicant("sensor"), NOW + 60));
        assert!(!invites.arrived(&secret, applicant("other"), NOW + 120), "nobody else after");
        assert_eq!(invites.open(NOW + 120).count(), 0, "and its rendezvous is no longer dialled");
        assert_eq!(invites.all().first().unwrap().standing(NOW + 120), Standing::Requested);
    }

    #[test]
    fn a_request_outlives_the_invites_expiry() {
        let record = record();
        let secret = record.invite.secret;
        let mut invites = Invites::default();
        invites.add(record);
        assert!(invites.arrived(&secret, applicant("sensor"), NOW + 60));
        let later = NOW + 3 * DEFAULT_LIFETIME_SECS;
        assert_eq!(
            invites.all().first().unwrap().standing(later),
            Standing::Requested,
            "still pending"
        );
        invites.forget_ended(later);
        assert_eq!(invites.all().len(), 1, "and never forgotten while it waits");
        assert!(invites.approve(&secret, later), "approved past the expiry");
        assert_eq!(invites.delivering(later).count(), 1);
        assert!(invites.delivered(&secret));
        assert_eq!(invites.all().first().unwrap().standing(later), Standing::Used);
    }

    #[test]
    fn an_expired_invite_takes_no_request() {
        let record = record();
        let secret = record.invite.secret;
        let mut invites = Invites::default();
        invites.add(record);
        assert!(!invites.arrived(&secret, applicant("sensor"), NOW + DEFAULT_LIFETIME_SECS));
        assert_eq!(invites.open(NOW + DEFAULT_LIFETIME_SECS).count(), 0);
    }

    #[test]
    fn a_rejected_request_admits_nobody_and_uses_the_invite() {
        let record = record();
        let secret = record.invite.secret;
        let mut invites = Invites::default();
        invites.add(record);
        assert!(invites.arrived(&secret, applicant("sensor"), NOW + 10));
        assert!(invites.reject(&secret, NOW + 20));
        assert!(!invites.approve(&secret, NOW + 30), "a rejected request is not approved later");
        assert_eq!(invites.all().first().unwrap().standing(NOW + 30), Standing::Rejected);
        assert_eq!(invites.open(NOW + 30).count(), 0, "and the invite takes no other");
    }

    #[test]
    fn a_withdrawn_invite_takes_no_request_and_nothing_signed_is_withdrawn() {
        let first = record();
        let secret = first.invite.secret;
        let mut invites = Invites::default();
        invites.add(first);
        assert!(invites.withdraw(&secret, NOW + 10));
        assert!(!invites.withdraw(&secret, NOW + 20), "withdrawn once");
        assert!(!invites.arrived(&secret, applicant("sensor"), NOW + 30));

        let second = record();
        let approved = second.invite.secret;
        invites.add(second);
        assert!(invites.arrived(&approved, applicant("sensor"), NOW + 10));
        assert!(invites.approve(&approved, NOW + 20));
        assert!(!invites.withdraw(&approved, NOW + 30), "an approval is in the roster already");
    }

    #[test]
    fn a_secret_never_issued_takes_nothing() {
        let mut invites = Invites::default();
        invites.add(record());
        assert!(!invites.arrived(&[0; enrollment::invite::SECRET_LEN], applicant("x"), NOW));
    }

    #[test]
    fn an_admin_is_never_invited_light() {
        let light_admin = Invited { role: Role::Admin, ..invited() };
        assert!(
            Record::issue(
                "k@relay:1",
                roster::id::NetworkId::from_bytes([7; 32]),
                light_admin,
                NOW,
                60
            )
            .is_err()
        );
    }

    #[test]
    fn the_record_is_kept_beside_the_log_and_reads_back() {
        let scratch = tempfile::tempdir().unwrap();
        let file = InviteFile::beside(&scratch.path().join("roster.log"));
        assert_eq!(file.load().unwrap(), Invites::default(), "none, before any is issued");
        let mut invites = Invites::default();
        invites.add(record());
        let requested = record();
        let secret = requested.invite.secret;
        invites.add(requested);
        assert!(invites.arrived(&secret, applicant("sensor"), NOW + 5));
        let approved = record();
        let other = approved.invite.secret;
        invites.add(approved);
        assert!(invites.arrived(&other, applicant("probe"), NOW + 6));
        assert!(invites.approve(&other, NOW + 7));
        file.save(&invites).unwrap();
        assert_eq!(file.load().unwrap(), invites);
    }

    #[test]
    fn ended_invites_are_forgotten_a_day_after() {
        let mut invites = Invites::default();
        invites.add(record());
        invites.forget_ended(NOW + DEFAULT_LIFETIME_SECS + 10);
        assert_eq!(invites.all().len(), 1, "kept for a day after it ended");
        invites.forget_ended(NOW + 3 * DEFAULT_LIFETIME_SECS);
        assert!(invites.all().is_empty());
    }
}

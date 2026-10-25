//! The invites an admin's device has issued, and what each is for.
//!
//! An invite carries only the relay, the network id and a secret. Who it is
//! for — the name, role, mode and groups the device will be admitted with — is
//! kept here, on the inviting device, with when it ends and whether it was
//! used or withdrawn. None of it enters the roster: it is this device's
//! promise to itself about one door it opened.
//!
//! An invite admits one device, once, before its expiry, unless withdrawn.
//! The expiry is measured on this device's clock, the only one that matters
//! for a door this device keeps.

use std::path::{Path, PathBuf};

use enrollment::Invite;
use roster::leaf::{Group, Mode};
use roster::types::Role;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The file the record is kept in, beside the network's log.
pub const FILE_NAME: &str = "invites.json";

/// How long an invite stays open unless the admin says otherwise: a day.
pub const DEFAULT_LIFETIME_SECS: u64 = 24 * 60 * 60;

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

/// One invite and what it is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The invite, secret included.
    pub invite: Invite,
    /// Who it is for.
    pub invited: Invited,
    /// When it ends, in seconds since the epoch on this device's clock.
    pub expires_at: u64,
    /// Whether it admitted its device.
    pub used: bool,
    /// Whether the admin withdrew it.
    pub withdrawn: bool,
}

/// Where an invite stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// It may still admit its device.
    Open,
    /// It admitted one already.
    Used,
    /// It ended at its expiry.
    Expired,
    /// The admin withdrew it.
    Withdrawn,
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
            used: false,
            withdrawn: false,
        })
    }

    /// Where it stands at `now`. A used or withdrawn invite says so whatever
    /// the time; past its expiry, an open one has ended.
    #[must_use]
    pub const fn standing(&self, now: u64) -> Standing {
        if self.withdrawn {
            Standing::Withdrawn
        } else if self.used {
            Standing::Used
        } else if now >= self.expires_at {
            Standing::Expired
        } else {
            Standing::Open
        }
    }

    /// Whether it may still admit its device.
    #[must_use]
    pub const fn admits(&self, now: u64) -> bool {
        matches!(self.standing(now), Standing::Open)
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

    /// The invites still open at `now`: the ones whose devices are dialled.
    pub fn open(&self, now: u64) -> impl Iterator<Item = &Record> {
        self.records.iter().filter(move |record| record.admits(now))
    }

    /// Keeps a new invite.
    pub fn add(&mut self, record: Record) {
        self.records.push(record);
    }

    /// The open invite with this secret, as its device arrives: taken, so it
    /// admits nobody else. Where it stands otherwise, when it is not open.
    ///
    /// # Errors
    ///
    /// Where the invite stands, when it does not admit; [`Standing::Expired`]
    /// for a secret this device never issued, which is no door either.
    pub fn take(
        &mut self,
        secret: &[u8; enrollment::invite::SECRET_LEN],
        now: u64,
    ) -> core::result::Result<Invited, Standing> {
        let Some(record) = self.records.iter_mut().find(|record| record.invite.secret == *secret)
        else {
            return Err(Standing::Expired);
        };
        match record.standing(now) {
            Standing::Open => {
                record.used = true;
                Ok(record.invited.clone())
            }
            other => Err(other),
        }
    }

    /// The open invite for the device to be called `name`, if there is one.
    #[must_use]
    pub fn open_named(&self, name: &str, now: u64) -> Option<&Record> {
        self.open(now).find(|record| record.invited.name == name)
    }

    /// Whether the invite with this secret is still open: what is checked
    /// before an admission it led to is signed.
    #[must_use]
    pub fn still_admits(&self, secret: &[u8; enrollment::invite::SECRET_LEN], now: u64) -> bool {
        self.records.iter().any(|record| record.invite.secret == *secret && record.admits(now))
    }

    /// Withdraws the invite with this secret. Whether one was open to withdraw.
    pub fn withdraw(&mut self, secret: &[u8; enrollment::invite::SECRET_LEN], now: u64) -> bool {
        self.records
            .iter_mut()
            .find(|record| record.invite.secret == *secret && record.admits(now))
            .is_some_and(|record| {
                record.withdrawn = true;
                true
            })
    }

    /// Forgets invites that ended more than a day ago, so the record does not
    /// grow without end.
    pub fn forget_ended(&mut self, now: u64) {
        self.records.retain(|record| {
            record.admits(now) || now < record.expires_at.saturating_add(DEFAULT_LIFETIME_SECS)
        });
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
    used: bool,
    withdrawn: bool,
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
            records.push(Record {
                invite,
                invited: Invited { name: one.name, role, mode, groups, ipv4 },
                expires_at: one.expires_at,
                used: one.used,
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
                used: record.used,
                withdrawn: record.withdrawn,
            })
            .collect();
        let encoded =
            serde_json::to_vec_pretty(&kept).map_err(|cause| self.failure(&cause.to_string()))?;
        crate::state::replace_file(&self.path, &encoded)
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

    #[test]
    fn an_open_invite_admits_its_device_once() {
        let record = record();
        let secret = record.invite.secret;
        let mut invites = Invites::default();
        invites.add(record);
        assert_eq!(invites.open(NOW).count(), 1);
        assert_eq!(invites.take(&secret, NOW + 60), Ok(invited()));
        assert_eq!(invites.take(&secret, NOW + 120), Err(Standing::Used), "nobody else after");
        assert_eq!(invites.open(NOW + 120).count(), 0, "and its device is no longer dialled");
    }

    #[test]
    fn an_expired_invite_admits_nobody() {
        let record = record();
        let secret = record.invite.secret;
        let mut invites = Invites::default();
        invites.add(record);
        assert_eq!(invites.take(&secret, NOW + DEFAULT_LIFETIME_SECS), Err(Standing::Expired));
        assert_eq!(invites.open(NOW + DEFAULT_LIFETIME_SECS).count(), 0);
    }

    #[test]
    fn a_withdrawn_invite_admits_nobody() {
        let record = record();
        let secret = record.invite.secret;
        let mut invites = Invites::default();
        invites.add(record);
        assert!(invites.withdraw(&secret, NOW + 10));
        assert!(!invites.withdraw(&secret, NOW + 20), "withdrawn once");
        assert_eq!(invites.take(&secret, NOW + 30), Err(Standing::Withdrawn));
    }

    #[test]
    fn a_secret_never_issued_admits_nobody() {
        let mut invites = Invites::default();
        invites.add(record());
        assert!(invites.take(&[0; enrollment::invite::SECRET_LEN], NOW).is_err());
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
        let mut used = record();
        used.used = true;
        invites.add(used);
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

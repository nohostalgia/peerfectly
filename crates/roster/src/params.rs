//! What a network's name suffix and overlay prefix may be.
//!
//! Both become configuration of every member's operating system. The suffix
//! decides which names a machine sends to the network's resolver — a whole branch
//! of the DNS, claimed on machines that did not choose it. The prefix becomes a
//! route into the tunnel. The roster already decides *who* may set them; this
//! decides *what* they may say, so that no network can take a public name away
//! from a member or route real hosts into its tunnel.
//!
//! The rules live here, once, and every layer that turns a parameter into
//! configuration calls these functions rather than restating them. A refusal
//! carries the rule it broke and never the value — a roster error has no room for
//! one — so naming what was refused is the job of the layer that shows it.

use crate::error::{Error, Result};

/// The only namespace a network suffix may sit under.
///
/// `internal` is the top-level name ICANN reserved in 2024 for private use: it can
/// never resolve on the public internet, so a rule for a name beneath it cannot
/// take a public name away from anybody.
pub const PRIVATE_PARENT: &str = "internal";

/// Names directly under [`PRIVATE_PARENT`] that widely deployed software already
/// answers for on the machines it runs on.
///
/// Docker Desktop answers for `host.docker.internal`, Google Cloud for
/// `metadata.google.internal`, AWS for `ec2.internal` and
/// `<region>.compute.internal`. A network claiming one of them breaks the machine
/// it is installed on. The list names what is widely deployed, not everything that
/// could be; adding to it refuses networks that were valid, so it changes only with
/// a proposal of its own.
pub const RESERVED_LABELS: &[&str] = &["docker", "google", "ec2", "compute"];

/// The longest a suffix may be, in bytes.
pub const MAX_SUFFIX_LEN: usize = crate::limits::MAX_SUFFIX_LEN;

/// The longest one label may be, in bytes — the DNS's own bound.
pub const MAX_LABEL_LEN: usize = 63;

/// How many bytes an overlay prefix has: a `/64`.
pub const PREFIX_LEN: usize = 8;

/// The first byte of every overlay prefix: RFC 4193's locally assigned range,
/// `fd00::/8`.
pub const PREFIX_FIRST_BYTE: u8 = 0xfd;

/// Whether a suffix is a private name a network may claim.
///
/// One or more labels, then [`PRIVATE_PARENT`]. A label is one to sixty-three
/// characters from lowercase `a`–`z`, digits and `-`, and does not begin or end
/// with `-`. The whole is at most [`MAX_SUFFIX_LEN`] bytes, and the label
/// immediately under the parent is not one of [`RESERVED_LABELS`].
///
/// There is one spelling: uppercase, a trailing dot and an empty label are
/// refused rather than normalised, because two spellings would be two parameter
/// values, and every other value in the roster has one encoding.
///
/// # Errors
///
/// [`Error::InvalidValue`] naming the rule that was broken.
pub fn private_suffix(suffix: &str) -> Result<()> {
    if suffix.len() > MAX_SUFFIX_LEN {
        return Err(Error::LimitExceeded("suffix length"));
    }
    if suffix.is_empty() {
        return Err(Error::InvalidValue("suffix is empty"));
    }

    // Checked label by label before anything about the parent, so an empty label
    // or an uppercase letter is reported as what it is rather than as a suffix
    // under the wrong namespace.
    let labels: Vec<&str> = suffix.split('.').collect();
    for label in &labels {
        well_formed_label(label)?;
    }

    let parent = [PRIVATE_PARENT];
    let Some(head_len) = labels.len().checked_sub(parent.len()) else {
        return Err(Error::InvalidValue("suffix not under a private namespace"));
    };
    let (head, tail) = labels.split_at(head_len);
    if tail != parent {
        return Err(Error::InvalidValue("suffix not under a private namespace"));
    }

    // A rule for the parent alone captures every private name on the machine,
    // including those that belong to other software.
    let Some(nearest) = head.last() else {
        return Err(Error::InvalidValue("suffix is a bare private namespace"));
    };
    if RESERVED_LABELS.contains(nearest) {
        return Err(Error::InvalidValue("suffix is a reserved name"));
    }
    Ok(())
}

/// Whether one label of a suffix is well formed.
fn well_formed_label(label: &str) -> Result<()> {
    if label.is_empty() {
        return Err(Error::InvalidValue("suffix has an empty label"));
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(Error::InvalidValue("suffix label too long"));
    }
    if !label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(Error::InvalidValue("suffix label malformed"));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(Error::InvalidValue("suffix label malformed"));
    }
    Ok(())
}

/// Whether an overlay prefix is a unique local `/64`.
///
/// Exactly [`PREFIX_LEN`] bytes beginning with [`PREFIX_FIRST_BYTE`]. A prefix in
/// global space would route real hosts into the tunnel; a shorter one would route
/// more of the unique local space than a network uses, including prefixes a home
/// router may have given itself; a longer one leaves no room for a device.
///
/// # Errors
///
/// [`Error::InvalidValue`] naming the rule that was broken.
pub fn unique_local_prefix(prefix: &[u8]) -> Result<()> {
    if prefix.first() != Some(&PREFIX_FIRST_BYTE) {
        return Err(Error::InvalidValue("prefix not unique local"));
    }
    if prefix.len() != PREFIX_LEN {
        return Err(Error::InvalidValue("prefix not a /64"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "a test reports failure by panicking"
)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn refused(suffix: &str) -> &'static str {
        match private_suffix(suffix) {
            Err(Error::InvalidValue(reason) | Error::LimitExceeded(reason)) => reason,
            other => panic!("expected `{suffix}` to be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_private_suffix_is_accepted() {
        for suffix in ["casa.internal", "lab.casa.internal", "prova-tel.internal", "a1.internal"] {
            assert!(private_suffix(suffix).is_ok(), "{suffix}");
        }
    }

    #[test]
    fn a_public_or_corporate_name_is_refused() {
        for suffix in ["com", "azienda.it", "banca.it", "intranet.example.com", "home.arpa"] {
            assert_eq!(refused(suffix), "suffix not under a private namespace", "{suffix}");
        }
    }

    /// A rule for the namespace alone would capture every private name on the
    /// machine.
    #[test]
    fn a_bare_private_parent_is_refused() {
        assert_eq!(refused("internal"), "suffix is a bare private namespace");
    }

    #[test]
    fn a_name_other_software_answers_for_is_refused() {
        for suffix in ["docker.internal", "google.internal", "ec2.internal", "compute.internal"] {
            assert_eq!(refused(suffix), "suffix is a reserved name", "{suffix}");
        }
    }

    /// Only the label right under the namespace is reserved: `host.docker.internal`
    /// sits beneath a reserved name and is refused, while `docker.casa.internal` is
    /// somebody's own network.
    #[test]
    fn a_suffix_beneath_a_reserved_name_is_refused_and_one_merely_containing_it_is_not() {
        assert_eq!(refused("host.docker.internal"), "suffix is a reserved name");
        assert_eq!(refused("eu-west-1.compute.internal"), "suffix is a reserved name");
        assert!(private_suffix("docker.casa.internal").is_ok());
    }

    #[test]
    fn a_suffix_has_one_spelling() {
        assert_eq!(refused("Casa.internal"), "suffix label malformed");
        assert_eq!(refused("casa.internal."), "suffix has an empty label");
        assert_eq!(refused("casa..internal"), "suffix has an empty label");
        assert_eq!(refused(".casa.internal"), "suffix has an empty label");
        assert_eq!(refused("-casa.internal"), "suffix label malformed");
        assert_eq!(refused("casa-.internal"), "suffix label malformed");
        assert_eq!(refused("casa_mia.internal"), "suffix label malformed");
        assert_eq!(refused("città.internal"), "suffix label malformed");
        assert_eq!(refused(""), "suffix is empty");
    }

    /// The DNS's own bound on a label. Under `.internal` the suffix's total bound
    /// is reached first — the longest label that fits is fifty-five characters —
    /// so the label rule is checked on its own, where it can be reached.
    #[test]
    fn a_label_may_be_sixty_three_characters_and_no_more() {
        assert!(well_formed_label(&"a".repeat(MAX_LABEL_LEN)).is_ok());
        assert_eq!(
            well_formed_label(&"a".repeat(MAX_LABEL_LEN + 1)),
            Err(Error::InvalidValue("suffix label too long"))
        );

        let fits = MAX_SUFFIX_LEN - ".internal".len();
        let longest = format!("{}.internal", "a".repeat(fits));
        assert!(private_suffix(&longest).is_ok(), "{longest}");
        let over = format!("{}.internal", "a".repeat(fits + 1));
        assert_eq!(refused(&over), "suffix length");
    }

    #[test]
    fn a_suffix_longer_than_the_roster_allows_is_refused() {
        let long = format!("{}.{}.internal", "a".repeat(40), "b".repeat(40));
        assert_eq!(refused(&long), "suffix length");
    }

    #[test]
    fn a_derived_prefix_is_accepted() {
        assert!(unique_local_prefix(&[0xfd, 1, 2, 3, 4, 5, 6, 7]).is_ok());
    }

    #[test]
    fn a_prefix_in_global_space_is_refused() {
        for first in [0x20, 0x2a, 0xfc, 0xfe, 0x00, 0xff] {
            let prefix = [first, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!(
                unique_local_prefix(&prefix),
                Err(Error::InvalidValue("prefix not unique local")),
                "{first:#04x}"
            );
        }
        assert_eq!(unique_local_prefix(&[]), Err(Error::InvalidValue("prefix not unique local")));
    }

    #[test]
    fn a_prefix_of_any_other_length_is_refused() {
        for len in [1_usize, 2, 4, 7, 9, 16] {
            let mut prefix = vec![0u8; len];
            prefix[0] = PREFIX_FIRST_BYTE;
            assert_eq!(
                unique_local_prefix(&prefix),
                Err(Error::InvalidValue("prefix not a /64")),
                "{len} bytes"
            );
        }
    }

    proptest! {
        /// Whatever is accepted is a private name: it ends in the private
        /// namespace, is not the namespace alone, and is neither a reserved name
        /// nor beneath one.
        #[test]
        fn an_accepted_suffix_is_always_private(suffix in "[a-z0-9.\\-]{0,70}") {
            if private_suffix(&suffix).is_ok() {
                prop_assert!(suffix.ends_with(".internal"), "{suffix}");
                prop_assert!(suffix != "internal");
                let labels: Vec<&str> = suffix.split('.').collect();
                let nearest = labels[labels.len() - 2];
                prop_assert!(!RESERVED_LABELS.contains(&nearest), "{suffix}");
                prop_assert!(suffix.len() <= MAX_SUFFIX_LEN);
            }
        }

        /// Arbitrary text is refused unless it is exactly the shape above.
        #[test]
        fn arbitrary_text_is_never_accepted_outside_the_namespace(suffix in ".{0,70}") {
            if private_suffix(&suffix).is_ok() {
                prop_assert!(suffix.ends_with(".internal"), "{suffix}");
                prop_assert!(suffix.is_ascii());
                prop_assert!(!suffix.bytes().any(|b| b.is_ascii_uppercase()));
            }
        }

        #[test]
        fn an_accepted_prefix_is_always_a_unique_local_64(prefix in proptest::collection::vec(any::<u8>(), 0..20)) {
            if unique_local_prefix(&prefix).is_ok() {
                prop_assert_eq!(prefix.len(), PREFIX_LEN);
                prop_assert_eq!(prefix[0], PREFIX_FIRST_BYTE);
            }
        }
    }
}

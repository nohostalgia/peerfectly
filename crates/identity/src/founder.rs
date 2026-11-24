//! The founder's words and the two keys they make.
//!
//! A network's founder is not a device. It is a person holding 12 words, from
//! which two Ed25519 keys are derived: a **signing** key that authors operations
//! and roots with an authority nothing in the network can take away, and a
//! **transport** key that opens a founder session, which carries the roster and
//! nothing else. The roster holds only their public halves, in the `founder`
//! parameter leaf.
//!
//! # The words
//!
//! BIP39: 128 bits of fresh randomness, a 4-bit checksum (the first bits of its
//! SHA-256), and the English list of 2048 words, 11 bits each — 12 words. 128
//! bits are as strong as the Ed25519 keys they make (offline-founder design
//! §19). 24 words, 256 bits and an 8-bit checksum, as networks founded before
//! were given, are read too. The list is embedded and checked against its
//! published SHA-256 by a test.
//!
//! A word is read in full or by its first four letters, which in the English
//! list name one word; in any letter case, with surrounding spaces. Nothing else
//! is corrected or guessed. A count other than 12 or 24, a word outside the list,
//! and a failing checksum are three different refusals, so a person is told
//! which.
//!
//! # The keys
//!
//! Each key's seed is `BLAKE3-derive(context, entropy)`, under a context of its
//! own: the same words always give the same two keys, the two are never one key,
//! and the words of one network give no other network's. BIP39's PBKDF2 seed is
//! not used: its stretching protects a low-entropy passphrase, and 256 random
//! bits need none. A context of our own also keeps these words from yielding a
//! key any wallet would derive from them.
//!
//! # Nothing is kept
//!
//! [`FounderKey`] holds its entropy and seeds in buffers that are overwritten
//! when it is dropped. It has no `Debug`, `Clone` or serialisation, and nothing
//! here writes it anywhere: the words exist in the memory of the process that
//! asked a person for them, for the act they were typed for, and no longer.

use roster::sign::{Ed25519Signer, Signer};
use roster::types::FounderKeys;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::secret::SecretBytes;

/// How many words founding makes.
pub const WORDS: usize = 12;

/// How many words networks founded before were given, still read.
pub const LONG_WORDS: usize = 24;

/// How many letters of a word name it in the English list.
pub const LETTERS_ENOUGH: usize = 4;

/// The BIP39 English list, one word per line, in its published order.
const LIST: &str = include_str!("bip39-english.txt");

/// The context the signing key's seed is derived under.
const SIGNING_CONTEXT: &str = "peerfectly founder signing key v1";

/// The context the transport key's seed is derived under.
const TRANSPORT_CONTEXT: &str = "peerfectly founder transport key v1";

/// Why words were not accepted as the founder's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordsRefusal {
    /// Neither 12 nor 24 words; how many there were.
    Count(usize),
    /// The word at this position, counted from 1, is not in the list.
    Unknown(usize),
    /// Every word is in the list, and together they fail their checksum: one
    /// was mistyped as another word of the list, or two were swapped.
    Checksum,
}

impl core::fmt::Display for WordsRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Count(count) => {
                write!(
                    f,
                    "the founder's words are {WORDS} (or {LONG_WORDS}), and {count} were given"
                )
            }
            Self::Unknown(position) => write!(f, "word {position} is not one of the list's words"),
            Self::Checksum => {
                f.write_str("the words do not check: wrong words, or in another order")
            }
        }
    }
}

/// The list, as a slice of words in their published order.
fn list() -> impl Iterator<Item = &'static str> {
    LIST.lines()
}

/// The word at `index` in the list.
///
/// # Panics
///
/// Never for an index below 2048: the list is embedded and checked.
#[must_use]
pub fn word(index: u16) -> &'static str {
    list().nth(usize::from(index)).unwrap_or("")
}

/// The index of `word` in the list, read in any letter case: the word in full,
/// or its first four letters, which name one word of the list.
#[must_use]
pub fn index_of(word: &str) -> Option<u16> {
    let wanted = Zeroizing::new(word.trim().to_ascii_lowercase());
    let at = list().position(|candidate| candidate == wanted.as_str()).or_else(|| {
        // Four letters, never fewer or a longer misspelling: a word cut short
        // is read, a word mistyped is not guessed at.
        (wanted.chars().count() == LETTERS_ENOUGH)
            .then(|| list().position(|candidate| candidate.starts_with(wanted.as_str())))
            .flatten()
    })?;
    u16::try_from(at).ok()
}

/// The founder's key, made from 12 words (or 24), held only in memory.
///
/// Not `Clone`, not `Debug`, not serialisable: there is no way to copy it out
/// but the words, which [`Self::word_indices`] gives back for showing once.
///
/// ```compile_fail
/// fn copies<T: Clone>() {}
/// copies::<identity::founder::FounderKey>();
/// ```
///
/// ```compile_fail
/// fn shows<T: core::fmt::Debug>() {}
/// shows::<identity::founder::FounderKey>();
/// ```
pub struct FounderKey {
    /// 16 bytes for 12 words, 32 for 24.
    entropy: Zeroizing<Vec<u8>>,
    signing: Ed25519Signer,
    transport: SecretBytes,
}

impl FounderKey {
    /// A new founder key from 128 bits of fresh randomness: 12 words.
    ///
    /// # Errors
    ///
    /// [`Error::NoEntropy`] when the operating system gives none.
    pub fn generate() -> Result<Self> {
        let mut entropy = Zeroizing::new([0u8; 16]);
        getrandom::fill(entropy.as_mut()).map_err(|_| Error::NoEntropy)?;
        Ok(Self::from_entropy(entropy.as_ref()))
    }

    /// The founder key the words given name.
    ///
    /// # Errors
    ///
    /// [`Error::FounderWords`] with the reason: neither 12 nor 24 words, a word
    /// outside the list (by its position), or a failing checksum.
    pub fn from_words<S: AsRef<str>>(words: &[S]) -> Result<Self> {
        if words.len() != WORDS && words.len() != LONG_WORDS {
            return Err(Error::FounderWords(WordsRefusal::Count(words.len())));
        }
        let mut indices = Zeroizing::new(Vec::with_capacity(words.len()));
        for (position, typed) in words.iter().enumerate() {
            indices.push(
                index_of(typed.as_ref()).ok_or(Error::FounderWords(WordsRefusal::Unknown(
                    position.saturating_add(1),
                )))?,
            );
        }
        let entropy = entropy_of(&indices)?;
        Ok(Self::from_entropy(&entropy))
    }

    /// The founder key the words in `text`, separated by spaces, name.
    ///
    /// # Errors
    ///
    /// As [`Self::from_words`].
    pub fn from_text(text: &str) -> Result<Self> {
        let words: Vec<&str> = text.split_whitespace().collect();
        Self::from_words(&words)
    }

    fn from_entropy(entropy: &[u8]) -> Self {
        let signing_seed = Zeroizing::new(blake3::derive_key(SIGNING_CONTEXT, entropy));
        let transport_seed = blake3::derive_key(TRANSPORT_CONTEXT, entropy);
        Self {
            entropy: Zeroizing::new(entropy.to_vec()),
            signing: Ed25519Signer::from_seed(*signing_seed),
            transport: SecretBytes::new(transport_seed),
        }
    }

    /// The words, as indices into the list, for showing to a person once: 12,
    /// or 24 for a key read from 24.
    #[must_use]
    pub fn word_indices(&self) -> Zeroizing<Vec<u16>> {
        indices_of(&self.entropy)
    }

    /// Whether `typed` is the word at `position`, counted from 1.
    #[must_use]
    pub fn is_word_at(&self, position: usize, typed: &str) -> bool {
        let indices = self.word_indices();
        let Some(expected) = position.checked_sub(1).and_then(|at| indices.get(at)) else {
            return false;
        };
        index_of(typed) == Some(*expected)
    }

    /// The two public keys, as the roster holds them.
    #[must_use]
    pub fn keys(&self) -> FounderKeys {
        let signing = self.signing.public_key();
        let transport = Ed25519Signer::from_seed(*self.transport.expose()).public_key();
        let signing: [u8; 32] = signing.as_bytes().try_into().unwrap_or([0; 32]);
        let transport: [u8; 32] = transport.as_bytes().try_into().unwrap_or([0; 32]);
        // Two seeds under two contexts cannot give one key; were they to, the
        // roster would refuse the pair, which is the right answer.
        FounderKeys::new(signing, transport).unwrap_or_else(|_| FounderKeys::held_by_nobody())
    }

    /// The signing key, for signing operations and roots as the founder.
    #[must_use]
    pub fn signer(&self) -> &dyn Signer {
        &self.signing
    }

    /// The transport key's seed, for the one founder session it opens.
    ///
    /// The only half of the founder key that may leave the process that asked
    /// for the words: it opens a session carrying the roster and signs nothing.
    #[must_use]
    pub const fn transport_seed(&self) -> &SecretBytes {
        &self.transport
    }
}

/// The bit at `at` of `bytes`, counted from the most significant bit of the
/// first byte.
fn bit_at(bytes: &[u8], at: usize) -> bool {
    let byte = bytes.get(at.wrapping_shr(3)).copied().unwrap_or(0);
    let shift = 7_u32.wrapping_sub(u32::try_from(at & 7).unwrap_or(0));
    byte.wrapping_shr(shift) & 1 == 1
}

/// Sets the bit at `at` of `bytes`, counted as [`bit_at`] counts.
fn set_bit(bytes: &mut [u8], at: usize) {
    let shift = 7_u32.wrapping_sub(u32::try_from(at & 7).unwrap_or(0));
    if let Some(byte) = bytes.get_mut(at.wrapping_shr(3)) {
        *byte |= 1_u8.wrapping_shl(shift);
    }
}

/// How many checksum bits `entropy_bytes` of entropy carry: one per 32 bits.
const fn checksum_bits(entropy_bytes: usize) -> usize {
    entropy_bytes.wrapping_mul(8).wrapping_div(32)
}

/// The word indices of the entropy, 16 bytes or 32: the bits, then the first
/// bits of their SHA-256, read 11 bits at a time — 12 words, or 24.
fn indices_of(entropy: &[u8]) -> Zeroizing<Vec<u16>> {
    let mut bits = Zeroizing::new(entropy.to_vec());
    bits.push(checksum_of(entropy));
    let total = entropy.len().wrapping_mul(8).wrapping_add(checksum_bits(entropy.len()));
    let mut indices = Zeroizing::new(Vec::with_capacity(total.wrapping_div(11)));
    for word in 0..total.wrapping_div(11) {
        let mut value: u16 = 0;
        for bit in 0..11_usize {
            let at = word.wrapping_mul(11).wrapping_add(bit);
            value = value.wrapping_shl(1) | u16::from(bit_at(bits.as_ref(), at));
        }
        indices.push(value);
    }
    bits.zeroize();
    indices
}

/// The entropy 12 or 24 word indices carry, checking their checksum.
fn entropy_of(indices: &[u16]) -> Result<Zeroizing<Vec<u8>>> {
    // 11 bits a word: 132 for 12 words, 264 for 24; one checksum bit per 32
    // bits of entropy, so the entropy is 32/33 of them.
    let total = indices.len().wrapping_mul(11);
    let entropy_bytes = total.wrapping_mul(32).wrapping_div(33).wrapping_div(8);
    let mut bits = Zeroizing::new(vec![0u8; entropy_bytes.wrapping_add(1)]);
    for (word, value) in indices.iter().enumerate() {
        for bit in 0..11_u32 {
            if value.wrapping_shr(10_u32.wrapping_sub(bit)) & 1 == 1 {
                let at = word.wrapping_mul(11).wrapping_add(usize::try_from(bit).unwrap_or(0));
                set_bit(bits.as_mut(), at);
            }
        }
    }
    let entropy = Zeroizing::new(bits.get(..entropy_bytes).unwrap_or_default().to_vec());
    // The checksum is the first bits of the hash: as many as were carried.
    let carried = checksum_bits(entropy_bytes);
    let dropped = 8_u32.wrapping_sub(u32::try_from(carried).unwrap_or(8));
    let typed = bits.get(entropy_bytes).copied().unwrap_or(0).wrapping_shr(dropped);
    let expected = checksum_of(&entropy).wrapping_shr(dropped);
    if typed != expected {
        return Err(Error::FounderWords(WordsRefusal::Checksum));
    }
    Ok(entropy)
}

/// The first byte of the entropy's SHA-256.
fn checksum_of(entropy: &[u8]) -> u8 {
    use sha2::Digest as _;
    sha2::Sha256::digest(entropy).first().copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "a test reports failure by panicking"
    )]

    use super::*;

    /// The embedded list is the published one, byte for byte.
    #[test]
    fn the_list_is_the_published_one() {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(LIST.as_bytes());
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");
        assert_eq!(list().count(), 2048);
    }

    fn words_of(entropy: &[u8]) -> String {
        indices_of(entropy).iter().map(|index| word(*index)).collect::<Vec<_>>().join(" ")
    }

    /// The reference vectors of BIP39 for 128-bit entropy, which founding
    /// makes, and back.
    #[test]
    fn the_128_bit_reference_vectors_give_their_words() {
        for (entropy, words) in [
            (
                [0x00; 16],
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            ),
            (
                [0x7f; 16],
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
            ),
            (
                [0x80; 16],
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            ),
            ([0xff; 16], "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"),
        ] {
            assert_eq!(words_of(&entropy), words);
            let key = FounderKey::from_text(words).unwrap();
            assert_eq!(key.entropy.as_slice(), &entropy[..]);
            assert_eq!(key.word_indices().len(), WORDS);
        }
    }

    /// Four letters name a word; fewer, or a word mistyped beyond them, do not.
    #[test]
    fn four_letters_are_enough_and_nothing_else_is_guessed() {
        let full = FounderKey::from_text(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .unwrap();
        let short =
            FounderKey::from_text("lega winn than year wave saus wort usef lega winn than yell")
                .unwrap();
        assert_eq!(full.keys(), short.keys());
        assert_eq!(index_of("ABAN"), index_of("abandon"));
        assert_eq!(index_of("aba"), None, "three letters name no word");
        assert_eq!(index_of("abandom"), None, "a misspelling is not guessed");
        assert_eq!(index_of("act"), index_of("act"), "a three-letter word is itself");
        assert!(index_of("act").is_some());
    }

    /// A key made now has 12 words, and reads back from them.
    #[test]
    fn a_founder_key_made_now_has_twelve_words() {
        let key = FounderKey::generate().unwrap();
        let words: Vec<&str> = key.word_indices().iter().map(|index| word(*index)).collect();
        assert_eq!(words.len(), WORDS);
        assert_eq!(FounderKey::from_words(&words).unwrap().keys(), key.keys());
    }

    /// The reference vectors of BIP39 for 256-bit entropy.
    #[test]
    fn the_reference_vectors_give_their_words() {
        assert_eq!(
            words_of(&[0x00; 32]),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon art"
        );
        assert_eq!(
            words_of(&[0x7f; 32]),
            "legal winner thank year wave sausage worth useful legal winner thank year wave \
             sausage worth useful legal winner thank year wave sausage worth title"
        );
        assert_eq!(
            words_of(&[0x80; 32]),
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd \
             amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"
        );
        assert_eq!(
            words_of(&[0xff; 32]),
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
             zoo zoo vote"
        );
    }

    #[test]
    fn the_words_give_back_the_entropy() {
        let key = FounderKey::generate().unwrap();
        let typed: Vec<&str> = key.word_indices().iter().map(|index| word(*index)).collect();
        let again = FounderKey::from_words(&typed).unwrap();
        assert_eq!(key.keys(), again.keys(), "the same words, the same keys");
    }

    #[test]
    fn words_are_read_in_any_case_with_spaces() {
        let text = words_of(&[0x7f; 32]).to_uppercase().replace(' ', "  \t ");
        assert!(FounderKey::from_text(&format!("  {text} ")).is_ok());
    }

    #[test]
    fn the_three_refusals_are_told_apart() {
        let good = words_of(&[0x7f; 32]);
        let mut words: Vec<&str> = good.split(' ').collect();

        assert_eq!(
            FounderKey::from_words(&words[..23]).err(),
            Some(Error::FounderWords(WordsRefusal::Count(23)))
        );

        words[6] = "notaword";
        assert_eq!(
            FounderKey::from_words(&words).err(),
            Some(Error::FounderWords(WordsRefusal::Unknown(7)))
        );

        let mut words: Vec<&str> = good.split(' ').collect();
        words[0] = "letter";
        assert_eq!(
            FounderKey::from_words(&words).err(),
            Some(Error::FounderWords(WordsRefusal::Checksum)),
            "a word of the list in the wrong place fails the checksum"
        );
    }

    #[test]
    fn the_two_keys_differ_and_differ_between_words() {
        let one = FounderKey::from_text(&words_of(&[0x7f; 32])).unwrap().keys();
        let other = FounderKey::from_text(&words_of(&[0x80; 32])).unwrap().keys();
        assert_ne!(one.signing(), one.transport());
        assert_ne!(one, other);
    }

    #[test]
    fn a_word_is_checked_by_its_position() {
        let key = FounderKey::from_text(&words_of(&[0x7f; 32])).unwrap();
        assert!(key.is_word_at(1, "legal"));
        assert!(key.is_word_at(24, "Title"));
        assert!(!key.is_word_at(2, "legal"));
        assert!(!key.is_word_at(0, "legal"));
        assert!(!key.is_word_at(25, "legal"));
    }

    #[test]
    fn the_founder_signs_what_the_roster_accepts_as_the_founders() {
        let key = FounderKey::from_text(&words_of(&[0x7f; 32])).unwrap();
        let keys = key.keys();
        assert_eq!(key.signer().key_id(), keys.signing_id());
    }
}

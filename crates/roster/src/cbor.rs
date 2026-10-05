//! Canonical CBOR: one byte encoding per logical value, and a reader that
//! refuses every other encoding.
//!
//! The rules implemented here are RFC 8949 §4.2.1 core deterministic encoding,
//! narrowed further:
//!
//! * definite-length items only — an indefinite-length marker is an error;
//! * minimal integer width — `5` encodes in one byte and nowhere else;
//! * map keys in canonical order, compared as *encoded* byte strings, which
//!   for the short text keys this format uses means shorter keys sort first
//!   and equal-length keys sort bytewise. This is **not** alphabetical order:
//!   `ts` precedes `alg`;
//! * no key outside the schema, no key repeated, no key missing;
//! * no trailing bytes after the top-level item.
//!
//! Rejection is always an error returned to the caller. Nothing here reorders,
//! deduplicates, or otherwise repairs input: two byte strings that differ must
//! never both decode to the same value, or the same logical operation would
//! reach the DAG under two different ids.
//!
//! The writer is built on `minicbor`, which emits minimal widths and definite
//! lengths. The reader parses item headers directly, because deciding whether
//! an encoding was minimal means looking at the header a general-purpose
//! decoder has already discarded. Both sides are written against RFC 8949
//! rather than against the library, so replacing `minicbor` stays contained.

use crate::error::{Error, Result};
use crate::limits;

/// CBOR major types this format uses.
mod major {
    /// Unsigned integer.
    pub const UINT: u8 = 0;
    /// Byte string.
    pub const BYTES: u8 = 2;
    /// Text string.
    pub const TEXT: u8 = 3;
    /// Array.
    pub const ARRAY: u8 = 4;
    /// Map.
    pub const MAP: u8 = 5;
    /// Simple values, including the two booleans.
    pub const SIMPLE: u8 = 7;
}

/// The encoded form of `false`.
const FALSE_BYTE: u8 = 0xf4;
/// The encoded form of `true`.
const TRUE_BYTE: u8 = 0xf5;

/// Compares two map keys the way canonical CBOR orders them.
///
/// Keys are compared as their *encoded* bytes. Every key in this format is a
/// text string shorter than [`limits::MAX_MAP_KEY_LEN`], so the header is a
/// single byte whose low bits are the length: comparing encoded bytes is
/// therefore comparing `(length, contents)`. Length dominates, which is why
/// `ts` sorts before `alg` and `body` before `author`.
#[must_use]
pub fn key_cmp(a: &str, b: &str) -> core::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

/// Reports whether a schema's field list is already in canonical key order.
///
/// Every schema in this crate is a hand-written constant; this is what keeps a
/// typo in one from silently changing the wire format.
#[must_use]
pub fn is_canonical_schema(schema: &[&str]) -> bool {
    schema.windows(2).all(|pair| match pair {
        [a, b] => key_cmp(a, b).is_lt() && b.len() <= limits::MAX_MAP_KEY_LEN,
        _ => true,
    })
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Builds canonical CBOR.
///
/// Encoding cannot fail. Values are validated against [`limits`] when they are
/// constructed, and the sink is an in-memory buffer whose write error type is
/// uninhabited, so there is no error path to propagate. That is deliberate: a
/// value that exists in memory is one that encodes.
pub struct Writer {
    enc: minicbor::Encoder<alloc_vec::Sink>,
}

/// Wraps `Vec<u8>` so the writer owns a concrete, infallible sink.
mod alloc_vec {
    /// An in-memory sink for encoded bytes.
    pub type Sink = Vec<u8>;
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl Writer {
    /// Starts an empty buffer.
    pub fn new() -> Self {
        Self { enc: minicbor::Encoder::new(Vec::new()) }
    }

    /// Writes an unsigned integer in its minimal width.
    pub fn u64(&mut self, value: u64) -> &mut Self {
        let _ = self.enc.u64(value);
        self
    }

    /// Writes a boolean.
    pub fn bool(&mut self, value: bool) -> &mut Self {
        let _ = self.enc.bool(value);
        self
    }

    /// Writes a byte string.
    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        let _ = self.enc.bytes(value);
        self
    }

    /// Writes a text string.
    pub fn str(&mut self, value: &str) -> &mut Self {
        let _ = self.enc.str(value);
        self
    }

    /// Writes a definite-length array header.
    pub fn array(&mut self, len: u64) -> &mut Self {
        let _ = self.enc.array(len);
        self
    }

    /// Writes a definite-length map header.
    pub fn map(&mut self, len: u64) -> &mut Self {
        let _ = self.enc.map(len);
        self
    }

    /// Writes a map key. Callers emit keys in schema order, which
    /// [`is_canonical_schema`] holds to canonical order.
    pub fn key(&mut self, name: &str) -> &mut Self {
        self.str(name)
    }

    /// Finishes, yielding the encoded bytes.
    pub fn finish(self) -> Vec<u8> {
        self.enc.into_writer()
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Reads canonical CBOR, rejecting anything else.
///
/// The reader is zero-copy: byte and text strings borrow the input buffer, so
/// the bytes a signature covers can be handed back to the caller as a slice of
/// exactly what arrived, never as a re-encoding.
///
/// The cursor is a shrinking slice rather than an index, so advancing it needs
/// no arithmetic that could wrap.
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Starts reading a buffer.
    pub fn new(input: &'a [u8]) -> Self {
        Self { rest: input }
    }

    /// Consumes exactly `n` bytes.
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, tail) = self.rest.split_at_checked(n).ok_or(Error::UnexpectedEof)?;
        self.rest = tail;
        Ok(head)
    }

    /// Consumes one byte.
    fn take_one(&mut self) -> Result<u8> {
        let (head, tail) = self.rest.split_first().ok_or(Error::UnexpectedEof)?;
        self.rest = tail;
        Ok(*head)
    }

    /// Reads an item header of the expected major type and returns its
    /// argument, rejecting non-minimal widths, indefinite lengths, and the
    /// reserved additional-information values.
    fn header(&mut self, expected_major: u8) -> Result<u64> {
        let first = self.take_one()?;
        let found_major = first >> 5;
        if found_major != expected_major {
            return Err(Error::TypeMismatch);
        }
        let info = first & 0x1f;
        match info {
            // Values 0..=23 are carried in the header byte itself, which is
            // the only minimal encoding for them.
            0..=23 => Ok(u64::from(info)),
            24 => {
                let value = u64::from(self.take_one()?);
                // Anything below 24 had a shorter encoding available.
                if value < 24 { Err(Error::NonCanonical) } else { Ok(value) }
            }
            25 => {
                let raw: [u8; 2] = self.take(2)?.try_into().map_err(|_| Error::UnexpectedEof)?;
                let value = u64::from(u16::from_be_bytes(raw));
                if value <= u64::from(u8::MAX) { Err(Error::NonCanonical) } else { Ok(value) }
            }
            26 => {
                let raw: [u8; 4] = self.take(4)?.try_into().map_err(|_| Error::UnexpectedEof)?;
                let value = u64::from(u32::from_be_bytes(raw));
                if value <= u64::from(u16::MAX) { Err(Error::NonCanonical) } else { Ok(value) }
            }
            27 => {
                let raw: [u8; 8] = self.take(8)?.try_into().map_err(|_| Error::UnexpectedEof)?;
                let value = u64::from_be_bytes(raw);
                if value <= u64::from(u32::MAX) { Err(Error::NonCanonical) } else { Ok(value) }
            }
            // 28..=30 are reserved; 31 is the indefinite-length marker. Both
            // are outside canonical form.
            _ => Err(Error::NonCanonical),
        }
    }

    /// Reads an unsigned integer.
    pub fn u64(&mut self) -> Result<u64> {
        self.header(major::UINT)
    }

    /// Reads a boolean. Any other simple value is a type mismatch: this format
    /// has no `null`, and an absent field is never a default.
    pub fn bool(&mut self) -> Result<bool> {
        let first = self.take_one()?;
        if first >> 5 != major::SIMPLE {
            return Err(Error::TypeMismatch);
        }
        match first {
            FALSE_BYTE => Ok(false),
            TRUE_BYTE => Ok(true),
            _ => Err(Error::TypeMismatch),
        }
    }

    /// Reads a length, rejecting it against `max` *before* the payload is
    /// touched.
    ///
    /// The order matters. Checking the bound first is what stops a peer from
    /// making this process reserve or walk a large buffer merely by claiming a
    /// large length; the claim is refused on its face.
    fn checked_len(&self, declared: u64, max: usize, which: &'static str) -> Result<usize> {
        let max_u64 = u64::try_from(max).map_err(|_| Error::LimitExceeded(which))?;
        if declared > max_u64 {
            return Err(Error::LimitExceeded(which));
        }
        usize::try_from(declared).map_err(|_| Error::LimitExceeded(which))
    }

    /// Reads a byte string no longer than `max`.
    pub fn bytes(&mut self, max: usize, which: &'static str) -> Result<&'a [u8]> {
        let declared = self.header(major::BYTES)?;
        let len = self.checked_len(declared, max, which)?;
        self.take(len)
    }

    /// Reads a byte string of exactly `len` bytes.
    ///
    /// Identifiers and signatures are fixed-width, and a short one is an error
    /// rather than a prefix: an id is never truncated.
    pub fn fixed_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let declared = self.header(major::BYTES)?;
        if declared != u64::try_from(len).map_err(|_| Error::IdentifierLength)? {
            return Err(Error::IdentifierLength);
        }
        self.take(len)
    }

    /// Reads a text string no longer than `max`.
    pub fn str(&mut self, max: usize, which: &'static str) -> Result<&'a str> {
        let declared = self.header(major::TEXT)?;
        let len = self.checked_len(declared, max, which)?;
        let raw = self.take(len)?;
        core::str::from_utf8(raw).map_err(|_| Error::InvalidUtf8)
    }

    /// Reads an array header, bounding the element count.
    pub fn array(&mut self, max: usize, which: &'static str) -> Result<usize> {
        let declared = self.header(major::ARRAY)?;
        self.checked_len(declared, max, which)
    }

    /// Opens a map whose fields are exactly `schema`, in that order.
    pub fn map(&mut self, schema: &'static [&'static str]) -> Result<MapReader<'_, 'a>> {
        debug_assert!(is_canonical_schema(schema), "schema is not in canonical key order");
        let declared = self.header(major::MAP)?;
        let count = usize::try_from(declared).map_err(|_| Error::UnknownField)?;
        // A map with the wrong number of entries cannot match the schema even
        // before the keys are read, and saying which way it is wrong is more
        // useful than a bare mismatch.
        match count.cmp(&schema.len()) {
            core::cmp::Ordering::Less => return Err(Error::MissingField),
            core::cmp::Ordering::Greater => return Err(Error::UnknownField),
            core::cmp::Ordering::Equal => {}
        }
        Ok(MapReader { reader: self, schema, position: 0, previous: None, declared: count })
    }

    /// Opens a map whose fields are `schema`, of which `optional` may be absent.
    ///
    /// Absence has one spelling: the key is not written. The entry count says
    /// which it is before any key is read, so a map one entry short is read
    /// without the optional field and a full map with it. Every other rule —
    /// order, duplicates, unknown keys — is the same as [`Self::map`].
    ///
    /// Any of the `optional` keys may be absent. Which ones are is found by
    /// looking at the next key rather than inferred from the count — a count
    /// can say *how many* are missing, and with more than one optional key it
    /// cannot say which.
    pub fn map_with_optional(
        &mut self,
        schema: &'static [&'static str],
        optional: &'static [&'static str],
    ) -> Result<MapReader<'_, 'a>> {
        debug_assert!(is_canonical_schema(schema), "schema is not in canonical key order");
        debug_assert!(
            optional.iter().all(|key| schema.contains(key)),
            "every optional key is part of the schema"
        );
        let declared = self.header(major::MAP)?;
        let count = usize::try_from(declared).map_err(|_| Error::UnknownField)?;
        if count < schema.len().saturating_sub(optional.len()) {
            return Err(Error::MissingField);
        }
        if count > schema.len() {
            return Err(Error::UnknownField);
        }
        Ok(MapReader { reader: self, schema, position: 0, previous: None, declared: count })
    }

    /// Asserts the whole buffer was consumed.
    pub fn finish(self) -> Result<()> {
        if self.rest.is_empty() { Ok(()) } else { Err(Error::TrailingData) }
    }
}

/// Reads the fields of one map in schema order.
///
/// Requiring the schema's exact order catches mis-ordering, duplication, an
/// unknown key, and a missing key with a single comparison per field, and lets
/// each be reported as the distinct thing it is.
pub struct MapReader<'r, 'a> {
    /// The underlying reader.
    reader: &'r mut Reader<'a>,
    /// Field names in canonical order.
    schema: &'static [&'static str],
    /// How many fields have been read.
    position: usize,
    /// The key read last, used to tell a duplicate from a mis-ordering.
    previous: Option<&'a str>,
    /// How many entries the map declared.
    declared: usize,
}

impl<'r, 'a> MapReader<'r, 'a> {
    /// Consumes the next key, which must be `expected`.
    pub fn key(&mut self, expected: &'static str) -> Result<&mut Reader<'a>> {
        let found = self.reader.str(limits::MAX_MAP_KEY_LEN, "map key length")?;
        if found != expected {
            return Err(self.classify(found));
        }
        self.previous = Some(found);
        self.position = self.position.saturating_add(1);
        Ok(self.reader)
    }

    /// Consumes an optional key, if this map carries it.
    ///
    /// # Errors
    ///
    /// As [`Self::key`], when the map carries the key and it is not next.
    pub fn optional_key(&mut self, expected: &'static str) -> Result<Option<&mut Reader<'a>>> {
        if self.position == self.declared {
            return Ok(None);
        }
        // Looked at, not consumed. A key that is not this one is left for the
        // next read, which classifies it — so an unknown or misplaced key is
        // still refused, just one field later.
        let before = self.reader.rest;
        let next = self.reader.str(limits::MAX_MAP_KEY_LEN, "map key length")?;
        self.reader.rest = before;
        if next != expected {
            return Ok(None);
        }
        self.key(expected).map(Some)
    }

    /// Explains why `found` is not the key the schema expects here.
    fn classify(&self, found: &str) -> Error {
        if self.previous == Some(found) {
            // The same key twice. The entry count already matched, so some
            // other field is necessarily absent, but the repetition is the
            // more specific and more useful complaint.
            Error::DuplicateKey
        } else if self.schema.contains(&found) {
            // A field of this schema, in the wrong place.
            Error::KeyOrdering
        } else {
            Error::UnknownField
        }
    }

    /// Asserts every field of the schema was read.
    pub fn finish(self) -> Result<()> {
        if self.position == self.declared {
            return Ok(());
        }
        // Entries remain that no field took, which is a key out of place rather
        // than one missing — an optional key written after where it belongs is
        // passed over when its turn comes, and is still here. The first one left
        // says which it was.
        let found = self.reader.str(limits::MAX_MAP_KEY_LEN, "map key length")?;
        Err(self.classify(found))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical order is length-first. This is the single easiest rule for a
    /// second implementation to get wrong, because it disagrees with the
    /// alphabetical order a programmer reaches for by habit.
    #[test]
    fn key_order_is_length_first_not_alphabetical() {
        assert!(key_cmp("ts", "alg").is_lt(), "shorter key must sort first");
        assert!("alg" < "ts", "and that is the opposite of alphabetical order");
        assert!(key_cmp("body", "type").is_lt());
        assert!(key_cmp("network", "parents").is_lt());
    }

    const OPTIONAL_SCHEMA: &[&str] = &["a", "bb", "ccc"];

    fn map_of(entries: &[(&str, u64)]) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.map(u64::try_from(entries.len()).unwrap_or(0));
        for (key, value) in entries {
            writer.key(key).u64(*value);
        }
        writer.finish()
    }

    fn read_optional(bytes: &[u8]) -> Result<(u64, Option<u64>, u64)> {
        let mut reader = Reader::new(bytes);
        let mut map = reader.map_with_optional(OPTIONAL_SCHEMA, &["bb"])?;
        let a = map.key("a")?.u64()?;
        let bb = match map.optional_key("bb")? {
            Some(value) => Some(value.u64()?),
            None => None,
        };
        let c = map.key("ccc")?.u64()?;
        map.finish()?;
        Ok((a, bb, c))
    }

    #[test]
    fn an_optional_key_may_be_absent_or_present() {
        assert_eq!(read_optional(&map_of(&[("a", 1), ("ccc", 3)])), Ok((1, None, 3)));
        assert_eq!(read_optional(&map_of(&[("a", 1), ("bb", 2), ("ccc", 3)])), Ok((1, Some(2), 3)));
    }

    #[test]
    fn an_optional_map_still_refuses_what_a_map_refuses() {
        assert_eq!(read_optional(&map_of(&[("a", 1)])), Err(Error::MissingField));
        assert_eq!(
            read_optional(&map_of(&[("a", 1), ("bb", 2), ("ccc", 3), ("dddd", 4)])),
            Err(Error::UnknownField)
        );
        assert_eq!(
            read_optional(&map_of(&[("a", 1), ("a", 1), ("ccc", 3)])),
            Err(Error::DuplicateKey)
        );
        assert_eq!(
            read_optional(&map_of(&[("a", 1), ("ccc", 3), ("bb", 2)])),
            Err(Error::KeyOrdering)
        );
    }

    /// **Two optional keys, and which one is missing is found, not inferred.**
    ///
    /// A count can say how many are absent and not which, which is why the
    /// reader looks at the next key instead. Every combination is read, and a
    /// misplaced optional key is still refused as misplaced.
    #[test]
    fn with_two_optional_keys_either_or_both_may_be_absent() {
        const TWO: &[&str] = &["a", "bb", "ccc", "dddd"];
        fn read(bytes: &[u8]) -> Result<(Option<u64>, Option<u64>)> {
            let mut reader = Reader::new(bytes);
            let mut map = reader.map_with_optional(TWO, &["bb", "dddd"])?;
            map.key("a")?.u64()?;
            let bb = match map.optional_key("bb")? {
                Some(value) => Some(value.u64()?),
                None => None,
            };
            map.key("ccc")?.u64()?;
            let dddd = match map.optional_key("dddd")? {
                Some(value) => Some(value.u64()?),
                None => None,
            };
            map.finish()?;
            Ok((bb, dddd))
        }

        assert_eq!(read(&map_of(&[("a", 1), ("ccc", 3)])), Ok((None, None)));
        assert_eq!(read(&map_of(&[("a", 1), ("bb", 2), ("ccc", 3)])), Ok((Some(2), None)));
        assert_eq!(read(&map_of(&[("a", 1), ("ccc", 3), ("dddd", 4)])), Ok((None, Some(4))));
        assert_eq!(
            read(&map_of(&[("a", 1), ("bb", 2), ("ccc", 3), ("dddd", 4)])),
            Ok((Some(2), Some(4)))
        );
        assert_eq!(
            read(&map_of(&[("a", 1), ("ccc", 3), ("bb", 2)])),
            Err(Error::KeyOrdering),
            "an optional key after where it belongs is misplaced, not missing"
        );
        assert_eq!(read(&map_of(&[("a", 1)])), Err(Error::MissingField));
    }

    /// A map without the optional key reads exactly as a plain map of the
    /// remaining keys would.
    #[test]
    fn a_map_without_the_optional_key_reads_as_a_plain_map() {
        let bytes = map_of(&[("a", 1), ("ccc", 3)]);
        let mut reader = Reader::new(&bytes);
        let mut map = reader.map(&["a", "ccc"]).unwrap_or_else(|_| unreachable!());
        let a = map.key("a").and_then(Reader::u64);
        let c = map.key("ccc").and_then(Reader::u64);
        assert_eq!((a, c), (Ok(1), Ok(3)));
        assert_eq!(read_optional(&bytes), Ok((1, None, 3)));
    }

    #[test]
    fn schema_checker_rejects_alphabetical_order() {
        assert!(is_canonical_schema(&["ts", "alg", "body"]));
        assert!(!is_canonical_schema(&["alg", "ts"]));
        assert!(!is_canonical_schema(&["body", "body"]));
    }

    /// Integers must use the narrowest header that fits. These are the four
    /// width boundaries where an encoder can drift into a wider form.
    #[test]
    fn writer_uses_minimal_integer_width() {
        let encode = |v: u64| {
            let mut w = Writer::new();
            w.u64(v);
            w.finish()
        };
        assert_eq!(encode(23), vec![0x17], "23 fits in the header byte");
        assert_eq!(encode(24), vec![0x18, 24], "24 needs one extra byte");
        assert_eq!(encode(255), vec![0x18, 0xff]);
        assert_eq!(encode(256), vec![0x19, 0x01, 0x00], "256 needs two");
        assert_eq!(encode(65_535), vec![0x19, 0xff, 0xff]);
        assert_eq!(encode(65_536), vec![0x1a, 0x00, 0x01, 0x00, 0x00], "65536 needs four");
        assert_eq!(encode(u64::from(u32::MAX)), vec![0x1a, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            encode(u64::from(u32::MAX) + 1),
            vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            "one past u32::MAX needs eight"
        );
    }

    #[test]
    fn reader_accepts_minimal_widths() {
        for (bytes, expected) in [
            (vec![0x17], 23u64),
            (vec![0x18, 24], 24),
            (vec![0x19, 0x01, 0x00], 256),
            (vec![0x1a, 0x00, 0x01, 0x00, 0x00], 65_536),
        ] {
            let mut r = Reader::new(&bytes);
            assert_eq!(r.u64(), Ok(expected));
            assert_eq!(r.finish(), Ok(()));
        }
    }

    /// The value 5 has exactly one encoding. Every wider spelling of it is an
    /// error, because two encodings of one value mean two ids for one
    /// operation.
    #[test]
    fn non_minimal_integer_is_rejected() {
        for wider in [
            vec![0x18, 0x05],
            vec![0x19, 0x00, 0x05],
            vec![0x1a, 0x00, 0x00, 0x00, 0x05],
            vec![0x1b, 0, 0, 0, 0, 0, 0, 0, 0x05],
        ] {
            let mut r = Reader::new(&wider);
            assert_eq!(r.u64(), Err(Error::NonCanonical), "{wider:02x?} must be refused");
        }
    }

    #[test]
    fn indefinite_length_is_rejected() {
        // 0x9f opens an indefinite-length array.
        let mut r = Reader::new(&[0x9f, 0x01, 0xff]);
        assert_eq!(r.array(4, "parents"), Err(Error::NonCanonical));
        // 0x5f opens an indefinite-length byte string.
        let mut r = Reader::new(&[0x5f, 0xff]);
        assert_eq!(r.bytes(8, "value"), Err(Error::NonCanonical));
    }

    #[test]
    fn reserved_additional_info_is_rejected() {
        for reserved in [0x1c_u8, 0x1d, 0x1e] {
            let input = [reserved];
            let mut r = Reader::new(&input);
            assert_eq!(r.u64(), Err(Error::NonCanonical));
        }
    }

    /// A schema of two one-byte keys, used by the map tests below.
    const PAIR: &[&str] = &["a", "b"];

    fn pair_map(entries: &[(&str, u64)]) -> Vec<u8> {
        let mut w = Writer::new();
        w.map(entries.len() as u64);
        for (k, v) in entries {
            w.key(k);
            w.u64(*v);
        }
        w.finish()
    }

    fn read_pair(bytes: &[u8]) -> Result<(u64, u64)> {
        let mut r = Reader::new(bytes);
        let mut m = r.map(PAIR)?;
        let a = m.key("a")?.u64()?;
        let b = m.key("b")?.u64()?;
        m.finish()?;
        Ok((a, b))
    }

    #[test]
    fn well_formed_map_reads() {
        assert_eq!(read_pair(&pair_map(&[("a", 1), ("b", 2)])), Ok((1, 2)));
    }

    #[test]
    fn out_of_order_keys_are_rejected() {
        assert_eq!(read_pair(&pair_map(&[("b", 2), ("a", 1)])), Err(Error::KeyOrdering));
    }

    #[test]
    fn duplicate_key_is_rejected() {
        // Both entries present in count, but the same key twice: neither
        // occurrence is taken.
        assert_eq!(read_pair(&pair_map(&[("a", 1), ("a", 2)])), Err(Error::DuplicateKey));
    }

    #[test]
    fn unknown_key_is_rejected() {
        assert_eq!(read_pair(&pair_map(&[("a", 1), ("z", 2)])), Err(Error::UnknownField));
    }

    #[test]
    fn missing_key_is_rejected() {
        assert_eq!(read_pair(&pair_map(&[("a", 1)])), Err(Error::MissingField));
    }

    #[test]
    fn extra_key_is_rejected() {
        assert_eq!(read_pair(&pair_map(&[("a", 1), ("b", 2), ("c", 3)])), Err(Error::UnknownField));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = pair_map(&[("a", 1), ("b", 2)]);
        bytes.push(0x00);
        let mut r = Reader::new(&bytes);
        let mut m = r.map(PAIR).expect("map opens");
        let _ = m.key("a").expect("a").u64();
        let _ = m.key("b").expect("b").u64();
        m.finish().expect("fields read");
        assert_eq!(r.finish(), Err(Error::TrailingData));
    }

    /// A declared length is refused on its face, before the payload is read.
    /// The input here claims four gigabytes and supplies nothing, so anything
    /// other than an immediate limit error means the reader tried to believe
    /// it.
    #[test]
    fn oversized_declared_length_is_refused_before_reading() {
        let claim_4gib = [0x5a, 0xff, 0xff, 0xff, 0xff];
        let mut r = Reader::new(&claim_4gib);
        assert_eq!(
            r.bytes(limits::MAX_OPERATION_SIZE, "operation size"),
            Err(Error::LimitExceeded("operation size")),
            "a huge claim must be refused, not attempted"
        );
        // The input carries no payload at all, so anything other than an
        // immediate refusal would have had to wait for bytes that never come.
    }

    #[test]
    fn array_count_is_bounded() {
        let mut w = Writer::new();
        w.array(u64::try_from(limits::MAX_PARENTS + 1).expect("fits"));
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        assert_eq!(
            r.array(limits::MAX_PARENTS, "parent count"),
            Err(Error::LimitExceeded("parent count"))
        );
    }

    #[test]
    fn fixed_width_identifier_rejects_short_and_long() {
        let mut w = Writer::new();
        w.bytes(&[0u8; 16]);
        let short = w.finish();
        let mut r = Reader::new(&short);
        assert_eq!(r.fixed_bytes(limits::ID_LEN), Err(Error::IdentifierLength));

        let mut w = Writer::new();
        w.bytes(&[0u8; 33]);
        let long = w.finish();
        let mut r = Reader::new(&long);
        assert_eq!(r.fixed_bytes(limits::ID_LEN), Err(Error::IdentifierLength));
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        // A text-string header over bytes that are not valid UTF-8.
        let mut r = Reader::new(&[0x62, 0xff, 0xfe]);
        assert_eq!(r.str(16, "name"), Err(Error::InvalidUtf8));
    }

    #[test]
    fn wrong_major_type_is_rejected() {
        let mut w = Writer::new();
        w.str("not a number");
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u64(), Err(Error::TypeMismatch));
    }

    #[test]
    fn truncated_input_is_rejected() {
        let mut r = Reader::new(&[0x19, 0x01]);
        assert_eq!(r.u64(), Err(Error::UnexpectedEof));
        let mut r = Reader::new(&[]);
        assert_eq!(r.u64(), Err(Error::UnexpectedEof));
    }

    proptest::proptest! {
        /// The reader is the first thing to touch bytes from the network, so
        /// it is the one place where a panic would be a remotely triggerable
        /// crash. Every input either parses or returns an error; none aborts.
        #[test]
        fn reader_never_panics_on_arbitrary_bytes(input in proptest::collection::vec(proptest::num::u8::ANY, 0..512)) {
            let mut r = Reader::new(&input);
            let _ = r.u64();
            let mut r = Reader::new(&input);
            let _ = r.bool();
            let mut r = Reader::new(&input);
            let _ = r.bytes(limits::MAX_OPERATION_SIZE, "bytes");
            let mut r = Reader::new(&input);
            let _ = r.str(limits::MAX_OPERATION_SIZE, "text");
            let mut r = Reader::new(&input);
            let _ = r.array(limits::MAX_PARENTS, "array");
            let mut r = Reader::new(&input);
            let _ = r.fixed_bytes(limits::ID_LEN);
            let mut r = Reader::new(&input);
            if let Ok(mut m) = r.map(PAIR)
                && let Ok(inner) = m.key("a") {
                    let _ = inner.u64();
                }
        }
    }

    #[test]
    fn booleans_round_trip_and_reject_other_simple_values() {
        for value in [true, false] {
            let mut w = Writer::new();
            w.bool(value);
            let bytes = w.finish();
            let mut r = Reader::new(&bytes);
            assert_eq!(r.bool(), Ok(value));
        }
        // 0xf6 is `null`, which this format does not use: an absent value is
        // never a default here.
        let mut r = Reader::new(&[0xf6]);
        assert_eq!(r.bool(), Err(Error::TypeMismatch));
    }
}

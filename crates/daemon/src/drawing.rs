//! How a report is drawn: entries that read as one thing, stacked.
//!
//! A block is a heading and the lines under it, with a rule down the left of
//! every one of them. The rule is what makes an entry an entry: a fault message
//! or a revocation's reason too long for a line continues *inside* its block
//! rather than looking like the start of a new one, and with several networks on
//! the screen the rule says which one is being read.
//!
//! # What may be aligned, and what may not
//!
//! Labels are ours. They are written in this crate, their widths are known here,
//! and they are padded to a column.
//!
//! **Values are not.** A device's name, a revocation's reason, a relay's address:
//! every one of them was written somewhere else and arrives here as text. Nothing
//! is ever aligned *after* a value, so a device cannot change where anything else
//! on the page sits by choosing what to call itself. That is also why there is no
//! table here and no display-width measurement: a column past a value would need
//! the width of that value in cells, and getting it wrong is how `東京` or a name
//! carrying an escaped character knocks a report crooked.
//!
//! Wrapping does count characters, because a line has to break somewhere. It is
//! the one place where a wide character makes a line look longer than it was
//! measured to be — which moves a break, and nothing else. No other line's shape
//! depends on it.
//!
//! # The characters
//!
//! `▌` and `│` are chosen here and never come from a report, so nothing in the
//! drawing can be influenced by another device. They reach a Windows console as
//! UTF-16 — the standard library converts before writing, so the console's code
//! page does not enter into it — and this crate already draws a scannable code
//! out of half blocks through the same path.

use core::fmt;

/// The rule beside a block's heading.
const HEADING_RULE: char = '▌';

/// The rule beside every other line of a block.
const BODY_RULE: char = '│';

/// How wide a line may be before it is wrapped.
///
/// Fixed rather than read from the terminal. Reading it would mean asking the
/// console its size — a dependency — and would make the same report render
/// differently in a pipe than on a screen, which is the thing that makes an
/// output impossible to reason about from a bug report.
///
/// Eighty because that is the width every terminal has, and because a report
/// that is read beside a stack trace or pasted into a message is read at that
/// width whatever the window is.
const WIDTH: usize = 80;

/// How far a label's column may be pushed before values start on their own line.
///
/// A guard, not a layout: every label in this crate is far shorter. It exists so
/// that a label added later without thinking cannot squeeze values against the
/// right margin.
const WIDEST_LABEL: usize = 24;

/// One entry, drawn as a heading and the lines beneath it.
#[derive(Debug, Clone, Default)]
pub struct Block {
    /// The heading, drawn beside [`HEADING_RULE`].
    heading: String,
    /// The lines beneath it, in order.
    lines: Vec<Line>,
}

/// A line within a block.
#[derive(Debug, Clone)]
enum Line {
    /// A label of ours and a value from anywhere.
    Labelled {
        /// Our word for it.
        label: String,
        /// What it says.
        value: String,
    },
    /// A line of its own: a warning, or something that has no label.
    Plain {
        /// The mark that opens it, such as `!`, or nothing.
        mark: Option<char>,
        /// The text.
        text: String,
    },
    /// A line of nothing, to separate what is beneath from what is above.
    Blank,
}

impl Block {
    /// A block under this heading.
    #[must_use]
    pub fn headed(heading: impl Into<String>) -> Self {
        Self { heading: heading.into(), lines: Vec::new() }
    }

    /// Adds a labelled line.
    pub fn line(&mut self, label: impl Into<String>, value: impl fmt::Display) {
        self.lines.push(Line::Labelled { label: label.into(), value: value.to_string() });
    }

    /// Adds a line with no label.
    pub fn plain(&mut self, text: impl fmt::Display) {
        self.lines.push(Line::Plain { mark: None, text: text.to_string() });
    }

    /// Adds a line that asks to be noticed.
    pub fn note(&mut self, text: impl fmt::Display) {
        self.lines.push(Line::Plain { mark: Some('!'), text: text.to_string() });
    }

    /// Adds an empty line, which keeps the rule.
    pub fn blank(&mut self) {
        self.lines.push(Line::Blank);
    }

    /// Whether anything has been added beneath the heading.
    #[must_use]
    pub fn is_bare(&self) -> bool {
        self.lines.is_empty()
    }

    /// How wide the label column is: the longest label in this block, bounded.
    ///
    /// Per block rather than per report, so a network with a long label in it
    /// does not push every other network's values across the page.
    fn label_column(&self) -> usize {
        self.lines
            .iter()
            .filter_map(|line| match line {
                Line::Labelled { label, .. } => Some(label.chars().count()),
                Line::Plain { .. } | Line::Blank => None,
            })
            .max()
            .unwrap_or(0)
            .min(WIDEST_LABEL)
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{HEADING_RULE} {}", self.heading)?;

        let column = self.label_column();
        for line in &self.lines {
            match line {
                Line::Labelled { label, value } => {
                    let padding = column.saturating_sub(label.chars().count());
                    let opener = format!("{BODY_RULE}   {label}{:padding$}   ", "");
                    let following = format!(
                        "{BODY_RULE}   {:width$}   ",
                        "",
                        width = column.saturating_add(padding).min(column)
                    );
                    write_wrapped(f, &opener, &following, value)?;
                }
                Line::Plain { mark, text } => {
                    let opener = match mark {
                        Some(mark) => format!("{BODY_RULE} {mark} "),
                        None => format!("{BODY_RULE}   "),
                    };
                    let following = format!("{BODY_RULE}     ");
                    write_wrapped(f, &opener, &following, text)?;
                }
                Line::Blank => writeln!(f, "{BODY_RULE}")?,
            }
        }
        Ok(())
    }
}

/// Writes `text` after `opener`, continuing after `following` for as long as it
/// takes.
///
/// A word longer than the room left is written whole and allowed past the
/// margin. Breaking one would break an address or a key in half, and an address
/// that cannot be copied out of a report in one piece is worse than a long line.
fn write_wrapped(
    f: &mut fmt::Formatter<'_>,
    opener: &str,
    following: &str,
    text: &str,
) -> fmt::Result {
    let room = WIDTH.saturating_sub(opener.chars().count()).max(1);
    let mut prefix = opener;
    let mut current = String::new();

    // Whether anything has been put on this line yet. Not "is the line empty":
    // a line that opens with indentation is not empty, and reading it as such
    // is how the indent that says *this belongs under the line above* is eaten.
    let mut started = false;

    for word in text.split(' ') {
        if !started {
            current.push_str(word);
            started = true;
            continue;
        }
        let would_be =
            current.chars().count().saturating_add(1).saturating_add(word.chars().count());
        if would_be > room {
            writeln!(f, "{prefix}{current}")?;
            prefix = following;
            current.clear();
            current.push_str(word);
        } else {
            current.push(' ');
            current.push_str(word);
        }
    }
    writeln!(f, "{prefix}{current}")
}

/// Whether a stored moment is the zero it was stored as when nothing was ever
/// recorded — a network never up here — rather than a moment at all.
///
/// Drawn as a date it reads `1970-01-01 (20726 days ago)`. The phone asks the
/// same question the same way (`Times.kt`, `isNothingKnown`).
#[must_use]
pub fn nothing_known(at: std::time::SystemTime) -> bool {
    at <= std::time::SystemTime::UNIX_EPOCH
}

/// A time as a person reads it: the local date and time to the minute, and how
/// far that is from now — `2026-09-30 23:55 (in 2 days)`.
///
/// Local to the machine this runs on, which for every view is the person's own:
/// the command line draws the report, not the daemon.
#[must_use]
pub fn when(at: std::time::SystemTime) -> String {
    when_in(at, std::time::SystemTime::now(), &chrono::Local)
}

/// [`when`], with the clock and the time zone given, so a test can fix both.
///
/// The zone, not an offset: the offset in force **at that instant** is the one
/// that applies, so a time across a change to or from summer time reads as the
/// clock on the wall said then.
///
/// A time that cannot be read — before 1970, or past what a date can hold — is
/// said to be unreadable, rather than shown as a date nobody set.
#[must_use]
pub fn when_in<Zone: chrono::TimeZone>(
    at: std::time::SystemTime,
    now: std::time::SystemTime,
    zone: &Zone,
) -> String
where
    Zone::Offset: fmt::Display,
{
    let since_1970 = |time: std::time::SystemTime| {
        time.duration_since(std::time::SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|since| i64::try_from(since.as_secs()).ok())
    };
    let Some(seconds) = since_1970(at) else {
        return "an unreadable time".to_owned();
    };
    let Some(instant) = chrono::DateTime::from_timestamp(seconds, 0) else {
        return "an unreadable time".to_owned();
    };
    let local = instant.with_timezone(zone).format("%Y-%m-%d %H:%M");
    match since_1970(now) {
        Some(now) => format!("{local} ({})", relative(seconds.saturating_sub(now))),
        None => local.to_string(),
    }
}

/// How far a time is from now, in the largest whole unit: `3 hours ago`,
/// `in 2 days`, or `just now` within a minute either way.
fn relative(ahead: i64) -> String {
    let apart = ahead.unsigned_abs();
    if apart < 60 {
        return "just now".to_owned();
    }
    let (count, unit) = match apart {
        ..3_600 => (apart / 60, "minute"),
        3_600..86_400 => (apart / 3_600, "hour"),
        _ => (apart / 86_400, "day"),
    };
    let plural = if count == 1 { "" } else { "s" };
    if ahead > 0 {
        format!("in {count} {unit}{plural}")
    } else {
        format!("{count} {unit}{plural} ago")
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "a test reports failure by panicking, and builds its own fixtures"
)]
mod tests {
    use super::*;

    /// **A time reads as a local date and how far from now**, in whole units,
    /// singular for one, and `in` for what is still to come.
    #[test]
    fn a_time_reads_as_a_date_and_a_distance() {
        use std::time::{Duration, SystemTime};

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_625_600); // 2026-09-28 20:00 UTC
        let rome = chrono::FixedOffset::east_opt(2 * 3_600).unwrap();
        let at = |ahead: i64| {
            if ahead >= 0 {
                now + Duration::from_secs(ahead.unsigned_abs())
            } else {
                now - Duration::from_secs(ahead.unsigned_abs())
            }
        };

        assert_eq!("2026-09-28 22:00 (just now)", when_in(now, now, &rome), "the zone's own clock");
        for (ahead, said) in [
            (-30, "just now"),
            (-60, "1 minute ago"),
            (-59 * 60, "59 minutes ago"),
            (-3_600, "1 hour ago"),
            (-23 * 3_600, "23 hours ago"),
            (-2 * 86_400, "2 days ago"),
            (2 * 86_400, "in 2 days"),
            (90, "in 1 minute"),
        ] {
            let drawn = when_in(at(ahead), now, &rome);
            assert!(drawn.ends_with(&format!("({said})")), "{ahead}: {drawn}");
        }
        assert!(when_in(at(2 * 86_400), now, &rome).starts_with("2026-09-30 22:00"));
    }

    /// A time before 1970 is not drawn as a date nobody set.
    #[test]
    fn an_impossible_time_is_said_to_be_unreadable() {
        use std::time::{Duration, SystemTime};

        let before = SystemTime::UNIX_EPOCH - Duration::from_secs(60);
        assert_eq!("an unreadable time", when_in(before, SystemTime::now(), &chrono::Utc));
    }

    fn lines(block: &Block) -> Vec<String> {
        block.to_string().lines().map(ToOwned::to_owned).collect()
    }

    #[test]
    fn a_block_is_a_heading_and_its_lines() {
        let mut block = Block::headed("prova-tel   up (now)");
        block.line("this device", "nas [a41f]");
        block.line("addresses", "fd01::7 / 100.117.31.3");

        assert_eq!(
            lines(&block),
            vec![
                "▌ prova-tel   up (now)",
                "│   this device   nas [a41f]",
                "│   addresses     fd01::7 / 100.117.31.3",
            ]
        );
    }

    /// Every line of a block carries the rule, including an empty one: the block
    /// is one thing, and a gap inside it must not read as the end of it.
    #[test]
    fn every_line_carries_the_rule() {
        let mut block = Block::headed("casa");
        block.line("relay", "none");
        block.blank();
        block.note("a device signed two histories");
        block.plain("peerfectly peers casa");

        for line in lines(&block).iter().skip(1) {
            assert!(line.starts_with(BODY_RULE), "{line}");
        }
        assert!(lines(&block).first().unwrap().starts_with(HEADING_RULE));
    }

    #[test]
    fn a_block_with_nothing_under_it_is_just_its_heading() {
        let block = Block::headed("casa   down");
        assert!(block.is_bare());
        assert_eq!(lines(&block), vec!["▌ casa   down"]);
    }

    #[test]
    fn a_block_of_one_line_needs_no_padding_beyond_its_own_label() {
        let mut block = Block::headed("casa");
        block.line("relay", "none");
        assert_eq!(lines(&block), vec!["▌ casa", "│   relay   none"]);
    }

    /// The point of the rule: a value too long for a line continues inside the
    /// block rather than looking like the beginning of the next one.
    #[test]
    fn a_wrapped_value_stays_inside_its_entry() {
        let mut block = Block::headed("casa");
        block.line(
            "recently",
            "the transport could not reach the relay and will try again shortly, which is \
             the ordinary state of a device that is switched off",
        );

        let drawn = lines(&block);
        assert!(drawn.len() > 2, "the value wrapped: {drawn:?}");
        for line in drawn.iter().skip(1) {
            assert!(line.starts_with(BODY_RULE), "every continuation keeps the rule: {line}");
        }
        // The continuation lines up under the value, not under the label.
        assert!(drawn[2].starts_with("│      "), "{}", drawn[2]);
    }

    /// Indentation inside a value is the caller saying "this belongs under the
    /// line above". Eating it flattens a nested detail into a sibling.
    #[test]
    fn a_line_that_opens_with_indentation_keeps_it() {
        let mut block = Block::headed("casa");
        block.plain("waiting:");
        block.plain("  revocation of stolen [0303]");
        block.plain("    laptop — not in contact");

        assert_eq!(
            lines(&block),
            vec![
                "▌ casa",
                "│   waiting:",
                "│     revocation of stolen [0303]",
                "│       laptop — not in contact",
            ]
        );
    }

    /// An address or a key is never broken in half. A line past the margin can be
    /// copied; half an address cannot.
    #[test]
    fn a_word_longer_than_the_line_is_not_broken() {
        let long =
            "peerfectly-join-v1:aGVsbG8gdGhlcmUgdGhpcyBpcyBhIHZlcnkgbG9uZyBwYXlsb2FkIGluZGVlZA";
        let mut block = Block::headed("casa");
        block.line("payload", long);

        let drawn = lines(&block);
        assert_eq!(drawn.len(), 2, "one line, however long: {drawn:?}");
        assert!(drawn[1].contains(long), "the word is whole");
    }

    /// Labels are ours, so they may be aligned. The column is the longest of
    /// them and nothing else.
    #[test]
    fn the_label_column_comes_from_our_labels_alone() {
        let mut block = Block::headed("casa");
        // Sentinels that appear in no label, so the column found is the value's.
        block.line("relay", "@");
        block.line("this device", "#");

        let drawn = lines(&block);
        let first = drawn[1].find('@').unwrap();
        let second = drawn[2].find('#').unwrap();
        assert_eq!(first, second, "values start in the same column: {drawn:?}");
    }

    /// The property the whole design exists for: a device cannot move anything
    /// on the page by choosing what to call itself.
    #[test]
    fn a_value_cannot_move_any_other_line() {
        let ordinary = {
            let mut block = Block::headed("casa");
            block.line("this device", "nas");
            block.line("relay", "203.0.113.10");
            lines(&block)
        };
        let hostile = {
            let mut block = Block::headed("casa");
            block.line("this device", "\\u{202e}gnol yrev a si siht\\u{202c} 東京 東京 東京");
            block.line("relay", "203.0.113.10");
            lines(&block)
        };

        assert_eq!(ordinary.first(), hostile.first(), "the heading is untouched");
        assert_eq!(
            ordinary.last(),
            hostile.last(),
            "the line after the hostile value is identical: {hostile:?}"
        );
    }

    /// A very long label cannot push values off the page either.
    #[test]
    fn the_label_column_is_bounded() {
        let mut block = Block::headed("casa");
        block.line("a".repeat(200), "value");
        let drawn = lines(&block);
        assert!(drawn[1].contains("value"), "{}", drawn[1]);
    }
}

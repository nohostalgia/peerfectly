//! The founder's words at a terminal: shown once and checked at founding, read
//! back one at a time when they are used.
//!
//! Founding shows the 12 words numbered, says what they are for and what they
//! cannot do, and asks for three of them by position, chosen at random. Nothing
//! is sent to the daemon until all three are right; a wrong answer shows the
//! words again and asks for three other positions, and an empty answer
//! abandons founding with nothing made. Afterwards the screen and its
//! scrollback are cleared, and that is said.
//!
//! Using the words reads them on one line, separated by spaces, each in full or
//! by its first four letters (offline-founder design §19). They are shown as
//! they are typed, so a typo is seen and corrected before Enter, and the screen
//! and its scrollback are cleared as soon as the line is read. Nothing turns the
//! terminal's echo off: an echo left off by an interrupted prompt used to hide
//! every answer typed after it.

use std::io::{BufRead, Write};

use identity::founder::{FounderKey, LETTERS_ENOUGH, LONG_WORDS, WORDS, word};
use zeroize::Zeroizing;

/// What the words are, said where they are shown.
pub const WHAT_THEY_ARE: &str = "\
These 12 words are the founder's key of this network. Write them down, in order, \
and keep them somewhere no device is.
  · They are the only way to repair the network if its admins are lost or stolen.
  · Whoever holds them controls the network.
  · They are shown only now. Lost, they cannot be recovered: the network goes on \
working, and can no longer be repaired once its admins are gone.";

/// The words, numbered, four to a line.
///
/// # Errors
///
/// When the terminal cannot be written to.
pub fn show(out: &mut dyn Write, key: &FounderKey) -> std::io::Result<()> {
    let indices = key.word_indices();
    writeln!(out)?;
    for (row, chunk) in indices.chunks(4).enumerate() {
        let mut line = String::new();
        for (column, index) in chunk.iter().enumerate() {
            let position = row.saturating_mul(4).saturating_add(column).saturating_add(1);
            line.push_str(&format!("{position:>3}. {:<10}", word(*index)));
        }
        writeln!(out, "  {}", line.trim_end())?;
    }
    writeln!(out)?;
    Ok(())
}

/// Three distinct positions from 1 to `count`, `pick(n)` giving a number below
/// `n`.
fn three_positions(count: usize, pick: &mut dyn FnMut(usize) -> usize) -> [usize; 3] {
    let mut chosen = [0_usize; 3];
    let mut filled = 0;
    while filled < 3 {
        let candidate = pick(count).min(count.saturating_sub(1)).saturating_add(1);
        if !chosen.contains(&candidate) {
            if let Some(slot) = chosen.get_mut(filled) {
                *slot = candidate;
            }
            filled = filled.saturating_add(1);
        }
    }
    chosen.sort_unstable();
    chosen
}

/// Shows the words and checks three of them, until three are right or the
/// person gives an empty answer.
///
/// # Errors
///
/// When the person abandons, or the terminal fails: nothing has been made.
pub fn show_and_check(
    out: &mut dyn Write,
    input: &mut dyn BufRead,
    key: &FounderKey,
    pick: &mut dyn FnMut(usize) -> usize,
) -> Result<(), String> {
    let io = |cause: std::io::Error| format!("the terminal failed: {cause}. Nothing was made.");
    writeln!(out, "{WHAT_THEY_ARE}").map_err(io)?;
    loop {
        show(out, key).map_err(io)?;
        let positions = three_positions(key.word_indices().len(), pick);
        writeln!(
            out,
            "To check they are written down, type the words asked for. An empty answer stops \
             here, and nothing is made."
        )
        .map_err(io)?;
        let mut all_right = true;
        for position in positions {
            write!(out, "word {position}: ").map_err(io)?;
            out.flush().map_err(io)?;
            let mut answer = Zeroizing::new(String::new());
            input.read_line(&mut answer).map_err(io)?;
            if answer.trim().is_empty() {
                return Err("founding stopped at the founder's words. Nothing was made.".to_owned());
            }
            all_right &= key.is_word_at(position, &answer);
        }
        if all_right {
            return Ok(());
        }
        writeln!(out, "\nThat is not what was shown. Here are the words again.").map_err(io)?;
    }
}

/// Clears the screen and its scrollback, and says so.
///
/// # Errors
///
/// When the terminal cannot be written to.
pub fn clear(out: &mut dyn Write) -> std::io::Result<()> {
    write!(out, "\x1b[2J\x1b[3J\x1b[H")?;
    writeln!(
        out,
        "The founder's words were cleared from this terminal and its scrollback. A terminal \
         that keeps its own record of what it showed is yours to close."
    )?;
    Ok(())
}

/// How many times the words may be typed again before nothing is signed.
const ATTEMPTS: usize = 3;

/// Reads the founder's words on one line from `input`, shown as typed, and
/// clears the terminal once the line is read.
///
/// A line that is not the words is said — the position of a word outside the
/// list, never the word; the count; or that they do not check — and asked
/// again, up to three times.
///
/// # Errors
///
/// When the person gives an empty line, the words are refused three times, or
/// the terminal fails.
pub fn read_back(out: &mut dyn Write, input: &mut dyn BufRead) -> Result<FounderKey, String> {
    let io = |cause: std::io::Error| format!("the terminal failed: {cause}. Nothing was signed.");
    writeln!(
        out,
        "The founder's words, on one line, separated by spaces: {WORDS} (or {LONG_WORDS}), each \
         in full or by its first {LETTERS_ENOUGH} letters. They are shown as you type and \
         cleared from this terminal once read. An empty line stops, and nothing is signed."
    )
    .map_err(io)?;
    for _ in 0..ATTEMPTS {
        write!(out, "words: ").map_err(io)?;
        out.flush().map_err(io)?;
        let mut line = Zeroizing::new(String::new());
        input.read_line(&mut line).map_err(io)?;
        // Cleared before anything else is said, whether the words were right.
        clear(out).map_err(io)?;
        if line.trim().is_empty() {
            return Err("stopped at the founder's words. Nothing was signed.".to_owned());
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        match FounderKey::from_words(&words) {
            Ok(key) => return Ok(key),
            Err(refusal) => writeln!(out, "{refusal}. Type them again.").map_err(io)?,
        }
    }
    Err("the founder's words were not given. Nothing was signed.".to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic,
        reason = "a test reports failure by panicking"
    )]

    use super::*;

    fn the_words(key: &FounderKey) -> Vec<&'static str> {
        key.word_indices().iter().map(|index| word(*index)).collect()
    }

    /// Positions 1, 2 and 3 the first time round, 4, 5 and 6 the next.
    fn counting() -> impl FnMut(usize) -> usize {
        let mut next: usize = 0;
        move |_| {
            let at = next;
            next = at.wrapping_add(1);
            at
        }
    }

    #[test]
    fn three_right_words_pass() {
        let key = FounderKey::generate().unwrap();
        let words = the_words(&key);
        let typed = format!("{}\n{}\n{}\n", words[0], words[1].to_uppercase(), words[2]);
        let mut out = Vec::new();
        show_and_check(&mut out, &mut typed.as_bytes(), &key, &mut counting()).unwrap();
        let shown = String::from_utf8(out).unwrap();
        assert!(shown.contains("Whoever holds them controls the network"));
        assert!(shown.contains(&format!("12. {}", words[11])), "twelve words, numbered");
    }

    #[test]
    fn a_wrong_word_shows_them_again_and_asks_for_others() {
        let key = FounderKey::generate().unwrap();
        let words = the_words(&key);
        let typed =
            format!("{}\nnope\n{}\n{}\n{}\n{}\n", words[0], words[2], words[3], words[4], words[5]);
        let mut out = Vec::new();
        show_and_check(&mut out, &mut typed.as_bytes(), &key, &mut counting()).unwrap();
        let shown = String::from_utf8(out).unwrap();
        assert!(shown.contains("not what was shown"));
        assert!(shown.contains("word 4: "), "three other positions the second time");
    }

    #[test]
    fn an_empty_answer_stops_with_nothing_made() {
        let key = FounderKey::generate().unwrap();
        let mut out = Vec::new();
        let stopped = show_and_check(&mut out, &mut "\n".as_bytes(), &key, &mut counting());
        assert!(stopped.unwrap_err().contains("Nothing was made"));
    }

    /// The words on one line give the key; a line with a word outside the list
    /// is said by position and asked again; the terminal is cleared after each.
    #[test]
    fn words_read_back_on_one_line_give_the_same_key() {
        let key = FounderKey::generate().unwrap();
        let words = the_words(&key);
        let mut wrong = words.clone();
        wrong[5] = "notaword";
        // The second time by their first four letters.
        let short: Vec<String> = words.iter().map(|word| word.chars().take(4).collect()).collect();
        let typed = format!("{}\n{}\n", wrong.join(" "), short.join("  "));
        let mut out = Vec::new();
        let again = read_back(&mut out, &mut typed.as_bytes()).unwrap();
        assert_eq!(again.keys(), key.keys());
        let shown = String::from_utf8(out).unwrap();
        assert!(shown.contains("word 6 is not one of the list's words"), "{shown}");
        assert!(!shown.contains("notaword"), "the word itself is never repeated");
        assert_eq!(shown.matches("\x1b[3J").count(), 2, "cleared after each line");
    }

    #[test]
    fn an_empty_line_stops_and_three_wrong_ones_sign_nothing() {
        let mut out = Vec::new();
        let Err(stopped) = read_back(&mut out, &mut "\n".as_bytes()) else { panic!("stopped") };
        assert!(stopped.contains("Nothing"), "{stopped}");
        let mut out = Vec::new();
        let Err(refused) = read_back(&mut out, &mut "a b\na b\na b\n".as_bytes()) else {
            panic!("refused")
        };
        assert!(refused.contains("Nothing was signed"), "{refused}");
    }
}

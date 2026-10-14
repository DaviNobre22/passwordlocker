//! Random password and passphrase generation.
//!
//! All randomness comes from the operating system through
//! [`crypto::random_array`]. Choices among N options go through
//! [`random_below`], which avoids the bias of a plain `random % N`.

use std::sync::OnceLock;

use zeroize::Zeroizing;

use crate::crypto::random_array;
use crate::error::{Error, Result};
use crate::secret::SecretString;

pub const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
pub const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const DIGITS: &str = "0123456789";
/// Symbols that nearly every site accepts. Quotes, backslash, backtick,
/// space, `<`, `>` and `|` are left out because they often break forms.
pub const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 128;
pub const MIN_WORDS: usize = 3;
pub const MAX_WORDS: usize = 20;

/// The EFF large wordlist: 7776 words, so each one adds log2(7776) bits.
const WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");

/// A uniformly random number in `0..n`, without modulo bias.
///
/// Taking `random % n` makes small results slightly more likely whenever `n`
/// does not divide 2^32. To avoid that, draws in the uneven leftover range at
/// the top are thrown away and redrawn. The chance of a redraw is below
/// `n / 2^32`, so the loop practically always ends on the first try.
pub fn random_below(n: u32) -> Result<u32> {
    if n == 0 {
        return Err(Error::InvalidGeneratorOptions("cannot choose from nothing"));
    }
    let n = u64::from(n);
    // The largest multiple of n that fits in the 2^32 possible draws.
    let limit = (1u64 << 32) / n * n;
    loop {
        let draw = u64::from(u32::from_le_bytes(random_array::<4>()?));
        if draw < limit {
            // `draw % n` is below n, which came from a u32.
            return Ok(u32::try_from(draw % n).unwrap_or(0));
        }
    }
}

fn random_index(len: usize) -> Result<usize> {
    let n = u32::try_from(len).map_err(|_| Error::InvalidGeneratorOptions("list too long"))?;
    Ok(random_below(n)? as usize)
}

/// Fisher-Yates shuffle: walk from the end, swapping each position with a
/// uniformly chosen one at or before it. Every ordering is equally likely.
fn shuffle<T>(items: &mut [T]) -> Result<()> {
    for i in (1..items.len()).rev() {
        let j = random_index(i + 1)?;
        items.swap(i, j);
    }
    Ok(())
}

/// Which characters a generated password may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CharOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for CharOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
        }
    }
}

impl CharOptions {
    fn selected_sets(&self) -> Vec<&'static str> {
        [
            (self.lowercase, LOWERCASE),
            (self.uppercase, UPPERCASE),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ]
        .into_iter()
        .filter_map(|(on, set)| on.then_some(set))
        .collect()
    }

    pub fn validate(&self) -> Result<()> {
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&self.length) {
            return Err(Error::InvalidGeneratorOptions(
                "length must be between 8 and 128",
            ));
        }
        if self.selected_sets().is_empty() {
            return Err(Error::InvalidGeneratorOptions(
                "select at least one kind of character",
            ));
        }
        Ok(())
    }

    /// Bits of entropy: length x log2(alphabet size).
    ///
    /// This is a close upper bound. Forcing one character from each selected
    /// set rules out a few passwords, which costs a fraction of a bit.
    /// Returns 0 for invalid options.
    pub fn entropy_bits(&self) -> f64 {
        let alphabet: usize = self.selected_sets().iter().map(|set| set.len()).sum();
        if alphabet == 0 {
            return 0.0;
        }
        self.length as f64 * (alphabet as f64).log2()
    }
}

/// Generates a password.
///
/// To guarantee at least one character from every selected set without
/// favouring any position: one character is drawn from each set, the rest of
/// the length is drawn from all selected sets together, and then the whole
/// list is shuffled. The shuffle makes the guaranteed characters land at
/// uniformly random positions.
pub fn generate_password(options: &CharOptions) -> Result<SecretString> {
    options.validate()?;
    let sets = options.selected_sets();
    let all: Vec<u8> = sets.iter().flat_map(|set| set.bytes()).collect();

    let mut chars: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(options.length));
    for set in &sets {
        chars.push(set.as_bytes()[random_index(set.len())?]);
    }
    while chars.len() < options.length {
        chars.push(all[random_index(all.len())?]);
    }
    shuffle(&mut chars[..])?;

    // Every byte is ASCII, so each one is one character.
    let mut text = String::with_capacity(chars.len());
    text.extend(chars.iter().map(|&byte| char::from(byte)));
    Ok(SecretString::new(text))
}

/// Settings for a passphrase made of random words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".to_owned(),
        }
    }
}

impl PassphraseOptions {
    pub fn validate(&self) -> Result<()> {
        if (MIN_WORDS..=MAX_WORDS).contains(&self.words) {
            Ok(())
        } else {
            Err(Error::InvalidGeneratorOptions(
                "the number of words must be between 3 and 20",
            ))
        }
    }

    /// Bits of entropy: words x log2(7776). The separator adds nothing,
    /// because an attacker is assumed to know it.
    pub fn entropy_bits(&self) -> f64 {
        self.words as f64 * (word_list().len() as f64).log2()
    }
}

/// The word list, parsed on first use and kept for the life of the program.
fn word_list() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        WORDLIST
            .lines()
            // Each line is `dice number<TAB>word`.
            .filter_map(|line| line.split('\t').nth(1))
            .map(str::trim)
            .filter(|word| !word.is_empty())
            .collect()
    })
}

pub fn generate_passphrase(options: &PassphraseOptions) -> Result<SecretString> {
    options.validate()?;
    let words = word_list();
    let mut chosen = Vec::with_capacity(options.words);
    for _ in 0..options.words {
        chosen.push(words[random_index(words.len())?]);
    }
    // Reserve the exact size up front so the text is never copied to a new
    // block while it is being built.
    let size = chosen.iter().map(|word| word.len()).sum::<usize>()
        + options.separator.len() * (chosen.len() - 1);
    let mut text = String::with_capacity(size);
    for (i, word) in chosen.iter().enumerate() {
        if i > 0 {
            text.push_str(&options.separator);
        }
        text.push_str(word);
    }
    Ok(SecretString::new(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_below_stays_in_range_and_rejects_zero() {
        for n in [1u32, 2, 3, 7, 100, 7776, u32::MAX] {
            for _ in 0..200 {
                assert!(random_below(n).unwrap() < n);
            }
        }
        assert!(random_below(0).is_err());
    }

    #[test]
    fn random_below_fills_buckets_evenly() {
        let mut counts = [0u32; 3];
        for _ in 0..30_000 {
            counts[random_below(3).unwrap() as usize] += 1;
        }
        // Expected 10000 each; a fair source stays far inside this window.
        for count in counts {
            assert!((9_000..=11_000).contains(&count), "{counts:?}");
        }
    }

    #[test]
    fn shuffle_keeps_all_items() {
        let mut items: Vec<u32> = (0..50).collect();
        shuffle(&mut items).unwrap();
        items.sort_unstable();
        assert_eq!(items, (0..50).collect::<Vec<_>>());
    }

    #[test]
    fn wordlist_has_7776_unique_words() {
        let words = word_list();
        assert_eq!(words.len(), 7776);
        let unique: std::collections::HashSet<_> = words.iter().collect();
        assert_eq!(unique.len(), 7776);
    }

    #[test]
    fn password_has_requested_length_and_every_selected_set() {
        let options = CharOptions {
            length: 8,
            ..CharOptions::default()
        };
        for _ in 0..200 {
            let password = generate_password(&options).unwrap();
            let text = password.expose();
            assert_eq!(text.len(), 8);
            for set in [LOWERCASE, UPPERCASE, DIGITS, SYMBOLS] {
                assert!(text.chars().any(|c| set.contains(c)), "{text}");
            }
        }
    }

    #[test]
    fn password_only_uses_selected_sets() {
        let options = CharOptions {
            length: 64,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
        };
        let password = generate_password(&options).unwrap();
        assert!(password.expose().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn invalid_options_are_refused() {
        for length in [7, 129] {
            let options = CharOptions {
                length,
                ..CharOptions::default()
            };
            assert!(generate_password(&options).is_err());
        }
        let none = CharOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..CharOptions::default()
        };
        assert!(generate_password(&none).is_err());
        assert_eq!(none.entropy_bits(), 0.0);
        for words in [2, 21] {
            let options = PassphraseOptions {
                words,
                ..PassphraseOptions::default()
            };
            assert!(generate_passphrase(&options).is_err());
        }
    }

    #[test]
    fn passphrase_has_requested_words_and_separator() {
        let options = PassphraseOptions {
            words: 5,
            separator: " ".into(),
        };
        let phrase = generate_passphrase(&options).unwrap();
        let parts: Vec<_> = phrase.expose().split(' ').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts.iter().all(|part| word_list().contains(part)));
    }

    #[test]
    fn entropy_matches_the_formulas() {
        let chars = CharOptions::default();
        // 26 + 26 + 10 + 24 = 86 characters, 20 long.
        assert!((chars.entropy_bits() - 20.0 * 86f64.log2()).abs() < 1e-9);
        let phrase = PassphraseOptions::default();
        assert!((phrase.entropy_bits() - 6.0 * 7776f64.log2()).abs() < 1e-9);
        assert!((phrase.entropy_bits() - 77.55).abs() < 0.01);
    }
}

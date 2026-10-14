//! The recovery code: a 32-byte key written so a person can print it, store
//! it on paper and type it back years later.
//!
//! Layout: the key as 52 Crockford base32 symbols, then two check symbols,
//! shown in groups of four separated by dashes:
//!
//! ```text
//! 0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ-0123-4567-89AB-CDEF-GH
//! ```

use zeroize::Zeroizing;

use crate::crypto::{KEY_LEN, Key};
use crate::error::{Error, Result};

/// Crockford's alphabet: no `I`, `L`, `O` or `U`, which are easy to confuse
/// with `1`, `0` and `V`, or to spell accidental words with.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 256 bits at 5 bits per symbol is 51.2, so 52 symbols. The last symbol
/// holds 1 key bit and 4 padding bits that must be zero.
const DATA_SYMBOLS: usize = 52;
const CHECK_SYMBOLS: usize = 2;
const TOTAL_SYMBOLS: usize = DATA_SYMBOLS + CHECK_SYMBOLS;
const GROUP: usize = 4;

/// Writes `key` as a recovery code.
pub fn encode(key: &Key) -> Zeroizing<String> {
    // Symbol values (0..32) are secret-derived, so the buffer is wiped too.
    let mut symbols = Zeroizing::new(Vec::with_capacity(TOTAL_SYMBOLS));

    // Bits are collected in `acc` and a symbol is emitted whenever 5 or more
    // are waiting. `acc` is a u16: it never holds more than 4 + 8 bits.
    let mut acc: u16 = 0;
    let mut bits = 0u32;
    for &byte in key.as_bytes() {
        acc = (acc << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            symbols.push(((acc >> bits) & 0x1F) as u8);
        }
        // Drop the bits already emitted so `acc` cannot overflow.
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        // Pad the leftover bit(s) on the right with zeros.
        symbols.push(((acc << (5 - bits)) & 0x1F) as u8);
    }
    debug_assert_eq!(symbols.len(), DATA_SYMBOLS);

    let (luhn, weighted) = check_symbols(&symbols);
    symbols.push(luhn);
    symbols.push(weighted);

    let mut text = Zeroizing::new(String::with_capacity(TOTAL_SYMBOLS + TOTAL_SYMBOLS / GROUP));
    for (i, &symbol) in symbols.iter().enumerate() {
        if i > 0 && i % GROUP == 0 {
            text.push('-');
        }
        text.push(char::from(ALPHABET[usize::from(symbol)]));
    }
    text
}

/// Reads a recovery code typed by a person.
///
/// Forgiving about spacing and case, and about the characters Crockford
/// declares interchangeable, but strict about everything else: a code that
/// decodes to the wrong key would only be noticed as a confusing "wrong
/// password or second factor" at unlock time.
pub fn decode(text: &str) -> Result<Key> {
    let mut symbols = Zeroizing::new(Vec::with_capacity(TOTAL_SYMBOLS));
    for ch in text.chars() {
        if ch == '-' || ch.is_whitespace() {
            continue;
        }
        symbols.push(symbol_value(ch).ok_or(Error::InvalidRecoveryCode)?);
        // Stop early so a huge input cannot grow the buffer without bound.
        if symbols.len() > TOTAL_SYMBOLS {
            return Err(Error::InvalidRecoveryCode);
        }
    }
    if symbols.len() != TOTAL_SYMBOLS {
        return Err(Error::InvalidRecoveryCode);
    }

    let (data, given) = symbols.split_at(DATA_SYMBOLS);
    let (luhn, weighted) = check_symbols(data);
    // Wrapping the comparison in one boolean keeps the control flow simple;
    // timing is irrelevant here because the check symbols are not secret
    // against anyone who can already time this call.
    if given != [luhn, weighted] {
        return Err(Error::InvalidRecoveryCode);
    }

    let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
    let mut out = 0;
    let mut acc: u16 = 0;
    let mut bits = 0u32;
    for &symbol in data {
        acc = (acc << 5) | u16::from(symbol);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if out == KEY_LEN {
                return Err(Error::InvalidRecoveryCode);
            }
            bytes[out] = ((acc >> bits) & 0xFF) as u8;
            out += 1;
            acc &= (1 << bits) - 1;
        }
    }
    // What is left over is the padding, which must be zero: otherwise two
    // different texts would decode to the same key.
    if out != KEY_LEN || acc != 0 {
        return Err(Error::InvalidRecoveryCode);
    }
    Ok(Key::from_bytes(&bytes))
}

/// Maps a typed character to its 5-bit value, applying Crockford's rules.
fn symbol_value(ch: char) -> Option<u8> {
    let upper = ch.to_ascii_uppercase();
    let upper = match upper {
        'I' | 'L' => '1',
        'O' => '0',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|&a| char::from(a) == upper)
        .map(|i| i as u8)
}

/// Two check symbols over the data symbols.
///
/// The first is the Luhn mod 32 check character, which catches every
/// single-symbol typo. Luhn mod 32 misses exactly one adjacent swap (`0` and
/// `Z`, whose doubled values collide), so a second symbol is added: the sum
/// of each symbol times its 1-based position, mod 32. Swapping neighbours
/// changes that sum by their difference, which is never zero for two
/// different symbols. The second symbol also covers the first, so swaps that
/// straddle the data/check boundary are caught as well.
fn check_symbols(data: &[u8]) -> (u8, u8) {
    let luhn = luhn_mod32(data);

    let mut sum: usize = 0;
    for (i, &symbol) in data.iter().chain(std::iter::once(&luhn)).enumerate() {
        sum += (i + 1) * usize::from(symbol);
    }
    (luhn, (sum % 32) as u8)
}

/// The Luhn mod N algorithm with N = 32: starting from the rightmost symbol,
/// double every other one, fold the result back into one base-32 digit, add
/// everything up, and pick the symbol that brings the total to a multiple of
/// 32.
fn luhn_mod32(data: &[u8]) -> u8 {
    let mut sum: u32 = 0;
    let mut factor = 2;
    for &symbol in data.iter().rev() {
        let addend = factor * u32::from(symbol);
        sum += addend / 32 + addend % 32;
        factor = 3 - factor;
    }
    ((32 - sum % 32) % 32) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key() -> Key {
        Key::generate().unwrap()
    }

    fn compact(code: &str) -> Vec<char> {
        code.chars().filter(|c| *c != '-').collect()
    }

    #[test]
    fn round_trips_many_random_keys() {
        for _ in 0..500 {
            let key = random_key();
            let code = encode(&key);
            assert_eq!(decode(&code).unwrap().as_bytes(), key.as_bytes());
        }
    }

    #[test]
    fn round_trips_extreme_keys() {
        for byte in [0x00, 0xFF, 0x01, 0x80] {
            let key = Key::from_bytes(&[byte; KEY_LEN]);
            let code = encode(&key);
            assert_eq!(decode(&code).unwrap().as_bytes(), key.as_bytes());
        }
    }

    #[test]
    fn has_expected_shape() {
        let code = encode(&Key::from_bytes(&[0u8; KEY_LEN]));
        // 54 symbols in groups of four: 13 full groups and one of two.
        assert_eq!(code.len(), 54 + 13);
        let groups: Vec<_> = code.split('-').collect();
        assert_eq!(groups.len(), 14);
        assert!(groups[..13].iter().all(|g| g.len() == 4));
        assert_eq!(groups[13].len(), 2);
        assert!(code.bytes().all(|b| b == b'-' || ALPHABET.contains(&b)));
    }

    #[test]
    fn known_vector_for_zero_key() {
        // All-zero data encodes as zeros; Luhn of zeros is zero and so is
        // the weighted sum.
        let code = encode(&Key::from_bytes(&[0u8; KEY_LEN]));
        assert_eq!(
            &*code,
            "0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-00"
        );
    }

    #[test]
    fn tolerates_spacing_case_and_lookalikes() {
        let key = random_key();
        let code = encode(&key);

        let spaced = code.replace('-', "  ");
        assert_eq!(decode(&spaced).unwrap().as_bytes(), key.as_bytes());

        let lower = code.to_lowercase();
        assert_eq!(decode(&lower).unwrap().as_bytes(), key.as_bytes());

        let squashed: String = code.chars().filter(|c| *c != '-').collect();
        assert_eq!(decode(&squashed).unwrap().as_bytes(), key.as_bytes());

        let padded = format!("\n  {}\t\n", *code);
        assert_eq!(decode(&padded).unwrap().as_bytes(), key.as_bytes());

        // I, L and O are accepted as 1, 1 and 0 (also in lower case).
        let swapped: String = code
            .chars()
            .map(|c| match c {
                '1' => 'I',
                '0' => 'o',
                other => other,
            })
            .collect();
        assert_eq!(decode(&swapped).unwrap().as_bytes(), key.as_bytes());
        let swapped_l: String = code
            .chars()
            .map(|c| if c == '1' { 'l' } else { c })
            .collect();
        assert_eq!(decode(&swapped_l).unwrap().as_bytes(), key.as_bytes());
    }

    #[test]
    fn rejects_malformed_input() {
        let code = encode(&random_key());
        let compact_code: String = compact(&code).into_iter().collect();

        let mut too_long = compact_code.clone();
        too_long.push('0');
        let too_short = &compact_code[..compact_code.len() - 1];
        let with_u = compact_code.replacen(&compact_code[..1], "U", 1);
        let with_dot = format!(".{}", &compact_code[1..]);
        let with_unicode = format!("é{}", &compact_code[1..]);

        for bad in [
            "",
            "-",
            "0000",
            too_short,
            too_long.as_str(),
            with_u.as_str(),
            with_dot.as_str(),
            with_unicode.as_str(),
        ] {
            assert!(
                matches!(decode(bad), Err(Error::InvalidRecoveryCode)),
                "accepted bad input of length {}",
                bad.len()
            );
        }
        // Absurdly long input is refused without building a huge buffer.
        assert!(decode(&"0".repeat(1_000_000)).is_err());
    }

    #[test]
    fn rejects_nonzero_padding_bits() {
        // Build a code whose last data symbol has a padding bit set but
        // whose check symbols are correct, so only the padding rule fails.
        let key = random_key();
        let code = encode(&key);
        let mut symbols: Vec<u8> = compact(&code)
            .iter()
            .map(|c| symbol_value(*c).unwrap())
            .collect();
        symbols.truncate(DATA_SYMBOLS);
        symbols[DATA_SYMBOLS - 1] |= 1;
        let (luhn, weighted) = check_symbols(&symbols);
        symbols.push(luhn);
        symbols.push(weighted);
        let text: String = symbols
            .iter()
            .map(|&s| char::from(ALPHABET[usize::from(s)]))
            .collect();
        assert!(matches!(decode(&text), Err(Error::InvalidRecoveryCode)));
    }

    #[test]
    fn detects_every_single_symbol_substitution() {
        for _ in 0..5 {
            let code = encode(&random_key());
            let symbols = compact(&code);
            for pos in 0..symbols.len() {
                for &replacement in ALPHABET {
                    let replacement = char::from(replacement);
                    if replacement == symbols[pos] {
                        continue;
                    }
                    let mut altered = symbols.clone();
                    altered[pos] = replacement;
                    let text: String = altered.into_iter().collect();
                    assert!(decode(&text).is_err(), "missed substitution at {pos}");
                }
            }
        }
    }

    #[test]
    fn detects_every_adjacent_transposition() {
        let mut codes: Vec<String> = (0..5).map(|_| encode(&random_key()).to_string()).collect();
        // Include the one pair plain Luhn mod 32 misses ('Z' next to '0'):
        // the first byte 0xF8 starts the code with symbols 11111 00000.
        let mut key_bytes = [0u8; KEY_LEN];
        key_bytes[0] = 0xF8;
        let tricky = encode(&Key::from_bytes(&key_bytes));
        assert!(tricky.starts_with("Z0"));
        codes.push(tricky.to_string());

        for code in codes {
            let symbols = compact(&code);
            for pos in 0..symbols.len() - 1 {
                if symbols[pos] == symbols[pos + 1] {
                    continue;
                }
                let mut altered = symbols.clone();
                altered.swap(pos, pos + 1);
                let text: String = altered.into_iter().collect();
                assert!(decode(&text).is_err(), "missed transposition at {pos}");
            }
        }
    }

    #[test]
    fn luhn_mod32_alone_misses_only_the_zero_z_swap() {
        // Documents why the second check symbol exists.
        let mut missed = Vec::new();
        for a in 0u8..32 {
            for b in 0u8..32 {
                if a != b && luhn_mod32(&[a, b, 7]) == luhn_mod32(&[b, a, 7]) {
                    missed.push((a, b));
                }
            }
        }
        assert_eq!(missed, [(0, 31), (31, 0)]);
    }
}

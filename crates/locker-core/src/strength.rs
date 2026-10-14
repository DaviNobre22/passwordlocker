//! The rule a master password must pass.

use unicode_normalization::{UnicodeNormalization, is_nfc};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Fewest characters a master password may have.
pub const MIN_MASTER_PASSWORD_CHARS: usize = 12;
/// Lowest accepted zxcvbn score, on its scale of 0 (guessed in about a
/// thousand tries) to 4.
const MIN_SCORE: zxcvbn::Score = zxcvbn::Score::Three;

/// The master password in Unicode normal form C (NFC).
///
/// The same visible text can be typed as different code point sequences: "é"
/// is one code point (U+00E9) on one keyboard or OS and "e" plus a combining
/// accent (U+0065 U+0301) on another. Their bytes differ, so without this
/// step the same password would derive different keys. NFC is applied
/// everywhere a master password enters [`crate::Locker`], so all spellings
/// of the text open the same vault. The result wipes itself on drop.
///
/// Passwords with only ASCII characters are unaffected. A vault made before
/// this rule existed with a decomposed password would no longer open; no
/// such vaults exist, which is why it could be added now.
pub(crate) fn normalize_password(password: &str) -> Zeroizing<String> {
    if is_nfc(password) {
        return Zeroizing::new(password.to_owned());
    }
    // Room for the usual growth up front, so the buffer is not reallocated
    // (which would leave an unwiped copy behind) while it fills.
    let mut out = Zeroizing::new(String::with_capacity(password.len().saturating_mul(3)));
    out.extend(password.nfc());
    out
}

/// Accepts a master password only if it has at least 12 characters AND
/// scores 3 or more on zxcvbn.
///
/// Length alone is not enough ("passwordpassword" is long and weak), and the
/// score alone can pass short strings, so both are required. This runs when a
/// vault is created and when its password is changed, never when unlocking,
/// so a vault made under older rules can always be opened.
///
/// The error carries zxcvbn's advice, which comes from fixed texts and
/// never repeats any part of the password.
pub fn check_master_password(password: &str) -> Result<()> {
    // Judge the text that will actually be used as the key.
    let password = normalize_password(password);
    let password = password.as_str();
    let long_enough = password.chars().count() >= MIN_MASTER_PASSWORD_CHARS;
    let estimate = zxcvbn::zxcvbn(password, &[]);
    if long_enough && estimate.score() >= MIN_SCORE {
        return Ok(());
    }

    let mut feedback = String::new();
    if !long_enough {
        feedback.push_str("Use at least 12 characters. ");
    }
    if let Some(advice) = estimate.feedback() {
        feedback.push_str(&advice.to_string());
    }
    if feedback.trim().is_empty() {
        feedback.push_str("Add more unrelated words or characters.");
    }
    Err(Error::WeakPassword {
        feedback: feedback.trim().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::{PassphraseOptions, generate_passphrase};

    #[test]
    fn common_password_is_rejected_with_advice() {
        let err = check_master_password("password123").unwrap_err();
        let Error::WeakPassword { feedback } = err else {
            panic!("expected WeakPassword");
        };
        assert!(!feedback.is_empty());
        assert!(!feedback.contains("password123"));
    }

    #[test]
    fn short_password_is_rejected_even_if_hard_to_guess() {
        assert!(check_master_password("q7#Zr!9").is_err());
    }

    #[test]
    fn normalization_makes_both_spellings_equal() {
        let composed = normalize_password("caf\u{e9}");
        let decomposed = normalize_password("cafe\u{301}");
        assert_eq!(*composed, *decomposed);
        assert_eq!(&*composed, "caf\u{e9}");
        assert_eq!(&*normalize_password("plain ascii"), "plain ascii");
    }

    #[test]
    fn generated_passphrase_is_accepted() {
        let phrase = generate_passphrase(&PassphraseOptions::default()).unwrap();
        check_master_password(phrase.expose()).unwrap();
    }
}

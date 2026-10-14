//! The rule a master password must pass.

use crate::error::{Error, Result};

/// Fewest characters a master password may have.
pub const MIN_MASTER_PASSWORD_CHARS: usize = 12;
/// Lowest accepted zxcvbn score, on its scale of 0 (guessed in about a
/// thousand tries) to 4.
const MIN_SCORE: zxcvbn::Score = zxcvbn::Score::Three;

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
    fn generated_passphrase_is_accepted() {
        let phrase = generate_passphrase(&PassphraseOptions::default()).unwrap();
        check_master_password(phrase.expose()).unwrap();
    }
}

//! A string that is wiped from memory when dropped.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

/// A piece of text that must not linger in memory (a password or a note).
///
/// `zeroize` has no serde support in the version we use, so serde is
/// implemented by hand below. It serializes as a plain JSON string.
///
/// Known limit: `serde_json` may leave transient copies of the text in its
/// own buffers while parsing. Those copies are outside this type's control.
#[derive(Clone, Default)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// The only way to read the text. The name makes every use easy to find
    /// when reviewing where secrets flow.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Hand-written so the text can never end up in a log by accident.
impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_the_text() {
        let secret = SecretString::new("hunter2");
        assert_eq!(format!("{secret:?}"), "SecretString(<redacted>)");
    }

    #[test]
    fn serializes_as_a_plain_string() {
        let secret = SecretString::new("hunter2");
        assert_eq!(serde_json::to_string(&secret).unwrap(), "\"hunter2\"");
        let back: SecretString = serde_json::from_str("\"hunter2\"").unwrap();
        assert_eq!(back.expose(), "hunter2");
    }
}

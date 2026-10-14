//! The entries stored in a vault and the types used to talk about them.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::crypto::random_array;
use crate::error::{Error, Result};
use crate::secret::SecretString;

/// How many replaced passwords an entry remembers. The oldest are dropped.
pub const MAX_PASSWORD_HISTORY: usize = 10;

/// A random 128-bit identifier, shown as 32 lowercase hex characters.
///
/// Random ids (instead of a counter) mean two copies of a vault that were
/// edited separately never hand out the same id for different entries.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntryId(String);

impl EntryId {
    pub fn generate() -> Result<Self> {
        let bytes = random_array::<16>()?;
        let mut hex = String::with_capacity(32);
        for byte in bytes {
            hex.push_str(&format!("{byte:02x}"));
        }
        Ok(Self(hex))
    }

    /// Checks that text coming from outside (the window) has the right shape.
    pub fn parse(text: &str) -> Result<Self> {
        let valid =
            text.len() == 32 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(Error::InvalidEntry("malformed entry id"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A password that was replaced, kept so a bad change can be undone.
#[derive(Clone, Serialize, Deserialize)]
pub struct PastPassword {
    pub password: SecretString,
    pub replaced_at: i64,
}

impl fmt::Debug for PastPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PastPassword")
            .field("password", &self.password)
            .field("replaced_at", &self.replaced_at)
            .finish()
    }
}

/// One saved login. Times are Unix seconds.
#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub id: EntryId,
    pub title: String,
    pub username: String,
    pub password: SecretString,
    pub url: String,
    pub notes: SecretString,
    #[serde(default)]
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Oldest first.
    #[serde(default)]
    pub password_history: Vec<PastPassword>,
}

// Hand-written: the secret fields are `SecretString`, which already hides
// itself, but spelling it out keeps notes and history out of logs even if
// someone later changes a field's type.
impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("password", &"<redacted>")
            .field("notes", &"<redacted>")
            .field("password_history", &self.password_history.len())
            .finish_non_exhaustive()
    }
}

/// What the window gets when it lists entries. It deliberately has no
/// password, notes or history: those are only sent one at a time, on request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EntrySummary {
    pub id: EntryId,
    pub title: String,
    pub username: String,
    pub url: String,
    pub tags: Vec<String>,
    pub updated_at: i64,
}

impl From<&Entry> for EntrySummary {
    fn from(entry: &Entry) -> Self {
        Self {
            id: entry.id.clone(),
            title: entry.title.clone(),
            username: entry.username.clone(),
            url: entry.url.clone(),
            tags: entry.tags.clone(),
            updated_at: entry.updated_at,
        }
    }
}

/// The fields a user fills in to add or edit an entry.
#[derive(Clone, Default)]
pub struct EntryDraft {
    pub title: String,
    pub username: String,
    pub password: SecretString,
    pub url: String,
    pub notes: SecretString,
    pub tags: Vec<String>,
}

impl fmt::Debug for EntryDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryDraft")
            .field("title", &self.title)
            .field("password", &"<redacted>")
            .field("notes", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl EntryDraft {
    /// Applies the rules every saved entry follows: the title is trimmed and
    /// must not be empty; tags are trimmed, empty ones dropped, and
    /// duplicates (ignoring case) removed, keeping the first spelling.
    pub(crate) fn normalized(mut self) -> Result<Self> {
        self.title = self.title.trim().to_owned();
        if self.title.is_empty() {
            return Err(Error::InvalidEntry("the title must not be empty"));
        }
        let mut seen = Vec::new();
        let mut tags = Vec::new();
        for tag in &self.tags {
            let tag = tag.trim();
            let key = tag.to_lowercase();
            if !tag.is_empty() && !seen.contains(&key) {
                seen.push(key);
                tags.push(tag.to_owned());
            }
        }
        self.tags = tags;
        Ok(self)
    }
}

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_32_lowercase_hex_chars_and_unique() {
        let a = EntryId::generate().unwrap();
        let b = EntryId::generate().unwrap();
        assert_eq!(a.as_str().len(), 32);
        assert!(
            a.as_str()
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(a, b);
        assert_eq!(EntryId::parse(a.as_str()).unwrap(), a);
        assert!(EntryId::parse("XYZ").is_err());
        assert!(EntryId::parse(&"A".repeat(32)).is_err());
    }

    #[test]
    fn debug_output_hides_secrets() {
        let draft = EntryDraft {
            title: "Mail".into(),
            password: SecretString::new("pw-secret"),
            notes: SecretString::new("note-secret"),
            ..EntryDraft::default()
        };
        let text = format!("{draft:?}");
        assert!(!text.contains("pw-secret") && !text.contains("note-secret"));
    }

    #[test]
    fn normalizing_cleans_title_and_tags() {
        let draft = EntryDraft {
            title: "  Mail  ".into(),
            tags: vec![" work ".into(), "".into(), "Work".into(), "home".into()],
            ..EntryDraft::default()
        };
        let draft = draft.normalized().unwrap();
        assert_eq!(draft.title, "Mail");
        assert_eq!(draft.tags, ["work", "home"]);

        let blank = EntryDraft {
            title: "   ".into(),
            ..EntryDraft::default()
        };
        assert!(matches!(blank.normalized(), Err(Error::InvalidEntry(_))));
    }
}

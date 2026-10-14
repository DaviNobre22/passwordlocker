//! The decrypted contents of a vault: the list of entries and the
//! operations on it. Nothing here touches the disk or the keys.

use std::io;
use std::mem;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::entry::{
    Entry, EntryDraft, EntryId, EntrySummary, MAX_PASSWORD_HISTORY, PastPassword, now_unix,
};
use crate::error::{Error, Result};
use crate::secret::SecretString;

/// Version of the JSON layout of the contents, separate from the file
/// format version so entries can change without touching the crypto.
pub const CONTENTS_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
pub struct VaultContents {
    version: u32,
    entries: Vec<Entry>,
}

impl Default for VaultContents {
    fn default() -> Self {
        Self::new()
    }
}

/// Only the version, read first so a newer layout gives a clear error
/// instead of a confusing complaint about a missing field.
#[derive(Deserialize)]
struct VersionOnly {
    version: u32,
}

impl VaultContents {
    pub fn new() -> Self {
        Self {
            version: CONTENTS_VERSION,
            entries: Vec::new(),
        }
    }

    /// Parses the plaintext returned by `UnlockedVault::open`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let VersionOnly { version } = serde_json::from_slice(bytes)
            .map_err(|_| Error::Malformed("the vault contents are not valid"))?;
        if version != CONTENTS_VERSION {
            return Err(Error::UnsupportedContentsVersion(version));
        }
        serde_json::from_slice(bytes)
            .map_err(|_| Error::Malformed("the vault contents are not valid"))
    }

    /// Serializes into a buffer that is wiped when dropped, ready for
    /// `UnlockedVault::seal`.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut writer = WipingBuffer::default();
        serde_json::to_writer(&mut writer, self)
            .map_err(|_| Error::Malformed("the vault contents could not be serialized"))?;
        Ok(writer.0)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn add(&mut self, draft: EntryDraft) -> Result<EntryId> {
        let draft = draft.normalized()?;
        let id = EntryId::generate()?;
        let now = now_unix();
        self.entries.push(Entry {
            id: id.clone(),
            title: draft.title,
            username: draft.username,
            password: draft.password,
            url: draft.url,
            notes: draft.notes,
            tags: draft.tags,
            created_at: now,
            updated_at: now,
            password_history: Vec::new(),
        });
        Ok(id)
    }

    /// Replaces the editable fields. The old password goes to the history
    /// only if it actually changed.
    pub fn update(&mut self, id: &EntryId, draft: EntryDraft) -> Result<()> {
        let draft = draft.normalized()?;
        let entry = self.entry_mut(id)?;
        let now = now_unix();
        if entry.password.expose() != draft.password.expose() {
            let replaced = mem::replace(&mut entry.password, draft.password);
            entry.password_history.push(PastPassword {
                password: replaced,
                replaced_at: now,
            });
            // Oldest first, so the excess is at the front.
            let excess = entry
                .password_history
                .len()
                .saturating_sub(MAX_PASSWORD_HISTORY);
            entry.password_history.drain(..excess);
        }
        entry.title = draft.title;
        entry.username = draft.username;
        entry.url = draft.url;
        entry.notes = draft.notes;
        entry.tags = draft.tags;
        entry.updated_at = now;
        Ok(())
    }

    pub fn delete(&mut self, id: &EntryId) -> Result<()> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.id == *id)
            .ok_or(Error::EntryNotFound)?;
        self.entries.remove(index);
        Ok(())
    }

    pub fn get(&self, id: &EntryId) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.id == *id)
    }

    /// All entries without their secrets, sorted by title ignoring case.
    pub fn summaries(&self) -> Vec<EntrySummary> {
        let mut list: Vec<&Entry> = self.entries.iter().collect();
        list.sort_by_cached_key(|entry| entry.title.to_lowercase());
        list.into_iter().map(EntrySummary::from).collect()
    }

    /// Case-insensitive substring search over title, username, URL and tags.
    /// The password and notes are never searched, so a search cannot be used
    /// to probe for them. An empty query matches everything.
    pub fn search(&self, query: &str) -> Vec<EntrySummary> {
        let query = query.trim().to_lowercase();
        let matches = |text: &str| text.to_lowercase().contains(&query);
        let mut found: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|entry| {
                query.is_empty()
                    || matches(&entry.title)
                    || matches(&entry.username)
                    || matches(&entry.url)
                    || entry.tags.iter().any(|tag| matches(tag))
            })
            .collect();
        found.sort_by_cached_key(|entry| entry.title.to_lowercase());
        found.into_iter().map(EntrySummary::from).collect()
    }

    pub fn summary(&self, id: &EntryId) -> Result<EntrySummary> {
        self.entry(id).map(EntrySummary::from)
    }

    // The three accessors below are what "reveal" calls: one secret at a
    // time, only when the user asks for it.

    pub fn password(&self, id: &EntryId) -> Result<&SecretString> {
        Ok(&self.entry(id)?.password)
    }

    pub fn notes(&self, id: &EntryId) -> Result<&SecretString> {
        Ok(&self.entry(id)?.notes)
    }

    pub fn password_history(&self, id: &EntryId) -> Result<&[PastPassword]> {
        Ok(&self.entry(id)?.password_history)
    }

    fn entry(&self, id: &EntryId) -> Result<&Entry> {
        self.get(id).ok_or(Error::EntryNotFound)
    }

    fn entry_mut(&mut self, id: &EntryId) -> Result<&mut Entry> {
        self.entries
            .iter_mut()
            .find(|entry| entry.id == *id)
            .ok_or(Error::EntryNotFound)
    }
}

/// A growing buffer that wipes the old memory every time it moves.
///
/// A plain `Vec` that outgrows its capacity copies itself to a new block and
/// frees the old one without erasing it, which would leave pieces of the
/// plaintext vault in freed memory. This writer grows by hand instead, so the
/// old block is always wiped.
#[derive(Default)]
struct WipingBuffer(Zeroizing<Vec<u8>>);

impl io::Write for WipingBuffer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let needed = self.0.len() + data.len();
        if needed > self.0.capacity() {
            let capacity = needed.max(self.0.capacity() * 2).max(4096);
            let mut bigger = Zeroizing::new(Vec::with_capacity(capacity));
            bigger.extend_from_slice(&self.0);
            // Assigning drops the old buffer, which wipes it.
            self.0 = bigger;
        }
        self.0.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(title: &str, password: &str) -> EntryDraft {
        EntryDraft {
            title: title.into(),
            username: "me@example.com".into(),
            password: SecretString::new(password),
            url: "https://example.com".into(),
            notes: SecretString::new("some note"),
            tags: vec!["work".into()],
        }
    }

    #[test]
    fn add_get_and_delete() {
        let mut contents = VaultContents::new();
        let id = contents.add(draft("Mail", "pw1")).unwrap();
        assert_eq!(contents.get(&id).unwrap().title, "Mail");
        assert_eq!(contents.password(&id).unwrap().expose(), "pw1");
        assert_eq!(contents.notes(&id).unwrap().expose(), "some note");

        contents.delete(&id).unwrap();
        assert!(contents.get(&id).is_none());
        assert!(matches!(contents.delete(&id), Err(Error::EntryNotFound)));
        assert!(matches!(contents.password(&id), Err(Error::EntryNotFound)));
    }

    #[test]
    fn empty_title_is_refused() {
        let mut contents = VaultContents::new();
        assert!(contents.add(draft("  ", "pw")).is_err());
        assert!(contents.is_empty());
    }

    #[test]
    fn update_records_history_only_when_password_changes() {
        let mut contents = VaultContents::new();
        let id = contents.add(draft("Mail", "pw1")).unwrap();

        contents.update(&id, draft("Mail 2", "pw1")).unwrap();
        assert!(contents.password_history(&id).unwrap().is_empty());
        assert_eq!(contents.get(&id).unwrap().title, "Mail 2");

        contents.update(&id, draft("Mail 2", "pw2")).unwrap();
        let history = contents.password_history(&id).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].password.expose(), "pw1");
        assert_eq!(contents.password(&id).unwrap().expose(), "pw2");
    }

    #[test]
    fn history_keeps_only_the_newest_ten() {
        let mut contents = VaultContents::new();
        let id = contents.add(draft("Mail", "pw0")).unwrap();
        for n in 1..=12 {
            contents
                .update(&id, draft("Mail", &format!("pw{n}")))
                .unwrap();
        }
        let history = contents.password_history(&id).unwrap();
        assert_eq!(history.len(), MAX_PASSWORD_HISTORY);
        // pw0 and pw1 were dropped; pw2 is now the oldest, pw11 the newest.
        assert_eq!(history[0].password.expose(), "pw2");
        assert_eq!(history[9].password.expose(), "pw11");
    }

    #[test]
    fn summaries_are_sorted_ignoring_case() {
        let mut contents = VaultContents::new();
        contents.add(draft("banana", "x")).unwrap();
        contents.add(draft("Cherry", "x")).unwrap();
        contents.add(draft("apple", "x")).unwrap();
        let titles: Vec<_> = contents
            .summaries()
            .into_iter()
            .map(|summary| summary.title)
            .collect();
        assert_eq!(titles, ["apple", "banana", "Cherry"]);
    }

    #[test]
    fn search_covers_visible_fields_but_never_secrets() {
        let mut contents = VaultContents::new();
        let mut d = draft("GitHub", "s3cr3t-pass");
        d.username = "octocat".into();
        d.url = "https://github.com".into();
        d.notes = SecretString::new("recovery-hint");
        d.tags = vec!["Dev".into()];
        contents.add(d).unwrap();
        contents.add(draft("Other", "pw")).unwrap();

        for query in ["github", "OCTO", "github.com", "dev"] {
            assert_eq!(contents.search(query).len(), 1, "query {query}");
        }
        assert!(contents.search("s3cr3t").is_empty());
        assert!(contents.search("recovery-hint").is_empty());
        assert_eq!(contents.search("").len(), 2);
    }

    #[test]
    fn bytes_round_trip_and_newer_version_is_refused() {
        let mut contents = VaultContents::new();
        let id = contents.add(draft("Mail", "pw1")).unwrap();
        let bytes = contents.to_bytes().unwrap();
        let back = VaultContents::from_bytes(&bytes).unwrap();
        assert_eq!(back.password(&id).unwrap().expose(), "pw1");

        let newer = br#"{"version":2,"entries":[{"unknown":"shape"}]}"#;
        assert!(matches!(
            VaultContents::from_bytes(newer),
            Err(Error::UnsupportedContentsVersion(2))
        ));
        assert!(VaultContents::from_bytes(b"not json").is_err());
    }

    #[test]
    fn wiping_buffer_matches_a_plain_serialization_for_large_contents() {
        let mut contents = VaultContents::new();
        for n in 0..200 {
            contents.add(draft(&format!("Entry {n}"), "pw")).unwrap();
        }
        let expected = serde_json::to_vec(&contents).unwrap();
        assert!(expected.len() > 4096);
        assert_eq!(&contents.to_bytes().unwrap()[..], &expected[..]);
    }
}

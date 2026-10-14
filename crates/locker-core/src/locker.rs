//! The one API the app uses: a vault file opened for reading and editing.
//!
//! A [`Locker`] ties together the file on disk, the keys that seal it and the
//! decrypted entries. Every change is saved straight away, so the file on
//! disk never lags behind what the user sees.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::contents::VaultContents;
use crate::crypto::{KdfParams, Key};
use crate::entry::{EntryDraft, EntryId, EntrySummary, PastPassword};
use crate::error::{Error, Result};
use crate::secret::SecretString;
use crate::storage::{DEFAULT_BACKUPS, read_file, write_with_backups};
use crate::strength::{check_master_password, normalize_password};
use crate::vault_file::{FactorKind, UnlockedVault};

/// Master passwords are normalised to Unicode NFC before they become a key
/// (see `normalize_password` in `strength.rs`), so "caf\u{e9}" and
/// "cafe\u{301}" open the same vault. This changes which key a non-ASCII
/// password derives, which was safe to do only because no real vaults
/// existed yet.
///
/// An open vault. Dropping it wipes the keys and the decrypted entries,
/// because every secret it owns zeroizes itself on drop.
pub struct Locker {
    path: PathBuf,
    vault: UnlockedVault,
    contents: VaultContents,
}

impl Locker {
    /// Creates a new vault file at `path`.
    ///
    /// Refuses to overwrite an existing file, rejects a master password that
    /// fails [`check_master_password`], and always uses
    /// [`KdfParams::DEFAULT`]: callers cannot choose weaker key derivation.
    pub fn create(path: &Path, password: &str, device: &Key, recovery: &Key) -> Result<Self> {
        Self::create_with_params(path, password, device, recovery, KdfParams::DEFAULT)
    }

    /// Same as [`Locker::create`] with chosen key derivation settings. It is
    /// private so that only this module's tests can use fast, weak settings.
    fn create_with_params(
        path: &Path,
        password: &str,
        device: &Key,
        recovery: &Key,
        kdf: KdfParams,
    ) -> Result<Self> {
        if path.exists() {
            return Err(Error::VaultExists);
        }
        check_master_password(password)?;
        let password = normalize_password(password);
        let locker = Self {
            path: path.to_path_buf(),
            vault: UnlockedVault::create(password.as_bytes(), kdf, device, recovery)?,
            contents: VaultContents::new(),
        };
        locker.save()?;
        Ok(locker)
    }

    /// Opens an existing vault with the master password and one second
    /// factor (the device key or the recovery key).
    pub fn open(path: &Path, password: &str, kind: FactorKind, factor: &Key) -> Result<Self> {
        let file = read_file(path)?;
        let password = normalize_password(password);
        let (vault, plaintext) = UnlockedVault::open(&file, password.as_bytes(), kind, factor)?;
        let contents = VaultContents::from_bytes(&plaintext)?;
        Ok(Self {
            path: path.to_path_buf(),
            vault,
            contents,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    // Each change below is followed by `save`. If saving fails the error is
    // returned and the change stays in memory, so the next successful save
    // writes it.

    pub fn add(&mut self, draft: EntryDraft) -> Result<EntryId> {
        let id = self.contents.add(draft)?;
        self.save()?;
        Ok(id)
    }

    pub fn update(&mut self, id: &EntryId, draft: EntryDraft) -> Result<()> {
        self.contents.update(id, draft)?;
        self.save()
    }

    pub fn delete(&mut self, id: &EntryId) -> Result<()> {
        self.contents.delete(id)?;
        self.save()
    }

    pub fn summaries(&self) -> Vec<EntrySummary> {
        self.contents.summaries()
    }

    pub fn search(&self, query: &str) -> Vec<EntrySummary> {
        self.contents.search(query)
    }

    pub fn summary(&self, id: &EntryId) -> Result<EntrySummary> {
        self.contents.summary(id)
    }

    pub fn password(&self, id: &EntryId) -> Result<&SecretString> {
        self.contents.password(id)
    }

    pub fn notes(&self, id: &EntryId) -> Result<&SecretString> {
        self.contents.notes(id)
    }

    pub fn password_history(&self, id: &EntryId) -> Result<&[PastPassword]> {
        self.contents.password_history(id)
    }

    /// Replaces the master password. Needs the current one, and the new one
    /// must pass the same strength rule as at creation.
    pub fn change_password(&mut self, current: &str, new: &str) -> Result<()> {
        check_master_password(new)?;
        let current = normalize_password(current);
        let new = normalize_password(new);
        self.vault
            .change_password(current.as_bytes(), new.as_bytes(), KdfParams::DEFAULT)?;
        self.save()
    }

    /// Lets another PC unlock this vault with its own device key.
    pub fn add_device(&mut self, device: &Key) -> Result<()> {
        self.vault.add_device(device)?;
        self.save()
    }

    /// Swaps in a new recovery key. The old recovery code stops working.
    pub fn replace_recovery(&mut self, recovery: &Key) -> Result<()> {
        self.vault.replace_recovery(recovery)?;
        self.save()
    }

    fn save(&self) -> Result<()> {
        // The serialized entries are wiped as soon as they are encrypted.
        let plaintext = self.contents.to_bytes()?;
        let file = self.vault.seal(&plaintext)?;
        write_with_backups(&self.path, &file, DEFAULT_BACKUPS)
    }
}

// Redacted by hand: only the path and counts are shown.
impl fmt::Debug for Locker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Locker")
            .field("path", &self.path)
            .field("vault", &self.vault)
            .field("entries", &self.contents.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "violet-anvil-quokka-drizzle-lantern-mosaic";
    const NEW_PASSWORD: &str = "tundra-biscuit-orbit-velvet-cobalt-nimbus";

    fn fast() -> KdfParams {
        KdfParams::new(8, 1, 1).unwrap()
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        path: PathBuf,
        device: Key,
        recovery: Key,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("vault.pwlk");
            Self {
                _dir: dir,
                path,
                device: Key::generate().unwrap(),
                recovery: Key::generate().unwrap(),
            }
        }

        fn create(&self) -> Locker {
            Locker::create_with_params(&self.path, PASSWORD, &self.device, &self.recovery, fast())
                .unwrap()
        }

        fn open(&self, password: &str) -> Result<Locker> {
            Locker::open(&self.path, password, FactorKind::Device, &self.device)
        }
    }

    fn draft(title: &str, password: &str) -> EntryDraft {
        EntryDraft {
            title: title.into(),
            username: "me".into(),
            password: SecretString::new(password),
            url: "https://example.com".into(),
            notes: SecretString::new("a private note"),
            tags: vec!["home".into()],
        }
    }

    #[test]
    fn entry_survives_reopening_with_device_and_recovery_keys() {
        let f = Fixture::new();
        let mut locker = f.create();
        let id = locker.add(draft("Mail", "pw1")).unwrap();
        drop(locker);

        let by_device = f.open(PASSWORD).unwrap();
        assert_eq!(by_device.summaries()[0].title, "Mail");
        assert_eq!(by_device.password(&id).unwrap().expose(), "pw1");

        let by_recovery =
            Locker::open(&f.path, PASSWORD, FactorKind::Recovery, &f.recovery).unwrap();
        assert_eq!(by_recovery.notes(&id).unwrap().expose(), "a private note");
    }

    #[test]
    fn update_keeps_history_and_delete_removes() {
        let f = Fixture::new();
        let mut locker = f.create();
        let id = locker.add(draft("Mail", "pw1")).unwrap();
        locker.update(&id, draft("Mail", "pw2")).unwrap();

        let reopened = f.open(PASSWORD).unwrap();
        assert_eq!(reopened.password(&id).unwrap().expose(), "pw2");
        let history = reopened.password_history(&id).unwrap();
        assert_eq!(history[0].password.expose(), "pw1");

        locker.delete(&id).unwrap();
        assert!(f.open(PASSWORD).unwrap().summaries().is_empty());
        assert!(matches!(locker.delete(&id), Err(Error::EntryNotFound)));
    }

    #[test]
    fn search_never_matches_password_or_notes() {
        let f = Fixture::new();
        let mut locker = f.create();
        locker.add(draft("Mail", "needle-password")).unwrap();
        assert!(locker.search("needle").is_empty());
        assert!(locker.search("private note").is_empty());
        assert_eq!(locker.search("mail").len(), 1);
    }

    #[test]
    fn create_refuses_an_existing_file() {
        let f = Fixture::new();
        f.create();
        let again = Locker::create_with_params(&f.path, PASSWORD, &f.device, &f.recovery, fast());
        assert!(matches!(again, Err(Error::VaultExists)));
    }

    #[test]
    fn weak_master_password_is_refused_and_nothing_is_written() {
        let f = Fixture::new();
        let result =
            Locker::create_with_params(&f.path, "password123", &f.device, &f.recovery, fast());
        assert!(matches!(result, Err(Error::WeakPassword { .. })));
        assert!(!f.path.exists());
    }

    #[test]
    fn change_password_then_reopen_with_the_new_one() {
        let f = Fixture::new();
        let mut locker = f.create();
        let id = locker.add(draft("Mail", "pw1")).unwrap();

        assert!(matches!(
            locker.change_password(PASSWORD, "password123"),
            Err(Error::WeakPassword { .. })
        ));
        assert!(matches!(
            locker.change_password("not the current one", NEW_PASSWORD),
            Err(Error::Unlock)
        ));

        // The real DEFAULT settings are used for the new key (about 1 s), so
        // the new vault can only be reopened with those same settings.
        locker.change_password(PASSWORD, NEW_PASSWORD).unwrap();
        assert!(matches!(f.open(PASSWORD), Err(Error::Unlock)));
        let reopened = f.open(NEW_PASSWORD).unwrap();
        assert_eq!(reopened.password(&id).unwrap().expose(), "pw1");
    }

    #[test]
    fn replace_recovery_and_add_device_are_saved() {
        let f = Fixture::new();
        let mut locker = f.create();
        let new_recovery = Key::generate().unwrap();
        let other_pc = Key::generate().unwrap();
        locker.replace_recovery(&new_recovery).unwrap();
        locker.add_device(&other_pc).unwrap();

        assert!(Locker::open(&f.path, PASSWORD, FactorKind::Recovery, &f.recovery).is_err());
        Locker::open(&f.path, PASSWORD, FactorKind::Recovery, &new_recovery).unwrap();
        Locker::open(&f.path, PASSWORD, FactorKind::Device, &other_pc).unwrap();
    }

    #[test]
    fn backups_exist_after_several_saves_and_each_opens() {
        let f = Fixture::new();
        let mut locker = f.create();
        for n in 0..4 {
            locker.add(draft(&format!("Entry {n}"), "pw")).unwrap();
        }
        // create + 4 adds = 5 saves, so 4 backups exist.
        for number in 1..=4 {
            let backup = f.path.with_file_name(format!("vault.pwlk.bak.{number}"));
            let opened = Locker::open(&backup, PASSWORD, FactorKind::Device, &f.device).unwrap();
            // .bak.1 is one save behind the live file, .bak.2 two, and so on.
            assert_eq!(opened.summaries().len(), 4 - number);
        }
    }

    #[test]
    fn debug_output_hides_everything_secret() {
        let f = Fixture::new();
        let mut locker = f.create();
        locker.add(draft("Mail", "needle-password")).unwrap();
        let text = format!("{locker:?}");
        assert!(!text.contains("needle-password") && !text.contains("private note"));
    }

    #[test]
    fn composed_and_decomposed_passwords_open_the_same_vault() {
        let f = Fixture::new();
        let composed = "caf\u{e9}-violet-anvil-quokka-drizzle-lantern";
        let decomposed = "cafe\u{301}-violet-anvil-quokka-drizzle-lantern";
        assert_ne!(composed, decomposed);
        Locker::create_with_params(&f.path, composed, &f.device, &f.recovery, fast()).unwrap();
        f.open(decomposed).unwrap();
        f.open(composed).unwrap();
    }

    #[test]
    fn create_uses_the_real_default_settings() {
        let f = Fixture::new();
        Locker::create(&f.path, PASSWORD, &f.device, &f.recovery).unwrap();
        let file = read_file(&f.path).unwrap();
        // m_cost (u32 LE) follows magic(4) + version(2) + kdf id(1).
        let m_cost = u32::from_le_bytes(file[7..11].try_into().unwrap());
        assert_eq!(m_cost, KdfParams::DEFAULT.m_cost_kib);
        f.open(PASSWORD).unwrap();
    }
}

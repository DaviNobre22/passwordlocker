//! Everything the window can ask for, as plain Rust with no Tauri types.
//!
//! `lib.rs` wraps each method in a thin Tauri command. Keeping the logic here
//! means it can be tested without opening a window, and keeps the security
//! boundary in one place: this is the only code that holds the unlocked
//! vault, and it decides what is allowed to cross to the window.
//!
//! Nothing in this module derives `Debug` for a type that holds a secret, and
//! errors only ever carry the `Display` text of the core errors, which never
//! contain secrets.

use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use locker_core::{
    CharOptions, EntryDraft, EntryId, EntrySummary, FactorKind, Key, Locker, PassphraseOptions,
    SecretString, check_master_password, decode_recovery_code, encode_recovery_code,
    generate_passphrase, generate_password,
};
use locker_device::DeviceKeyStore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// How long the vault may sit untouched before it locks itself.
pub const IDLE_LIMIT: Duration = Duration::from_secs(5 * 60);

/// A failure shown to the user. It wraps only display text from errors that
/// are known not to contain secrets.
#[derive(Debug)]
pub struct AppError(String);

impl AppError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    fn locked() -> Self {
        Self::new("the vault is locked")
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<locker_core::Error> for AppError {
    fn from(err: locker_core::Error) -> Self {
        Self(err.to_string())
    }
}

impl From<locker_device::DeviceError> for AppError {
    fn from(err: locker_device::DeviceError) -> Self {
        Self(err.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        Self(err.to_string())
    }
}

pub type AppResult<T> = std::result::Result<T, AppError>;

/// What the window learns about the app on start-up.
#[derive(Serialize)]
pub struct Status {
    pub vault_exists: bool,
    pub unlocked: bool,
    pub vault_path: String,
    pub setup_pending: bool,
}

/// An entry as sent by the edit form. `password` and `notes` are optional so
/// that editing an entry does not require the window to ever hold them:
/// `None` means "keep what is stored".
#[derive(Deserialize)]
pub struct DraftInput {
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// One replaced password, sent only when the user asks for the history.
#[derive(Serialize)]
pub struct PastPasswordView {
    pub password: String,
    pub replaced_at: i64,
}

/// A generated password or passphrase and how strong it is.
#[derive(Serialize)]
pub struct Generated {
    pub text: String,
    pub entropy_bits: f64,
}

#[derive(Deserialize)]
pub struct PasswordOptionsInput {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

#[derive(Deserialize)]
pub struct PassphraseOptionsInput {
    pub words: usize,
    #[serde(default)]
    pub separator: Option<String>,
}

/// A vault that has not been created yet. It exists only until the user
/// proves they saved the recovery code, so a crash or a closed window
/// between the two steps never leaves a vault nobody can recover.
struct PendingSetup {
    password: SecretString,
    recovery: Key,
}

pub struct AppState {
    vault_path: PathBuf,
    device: DeviceKeyStore,
    locker: Option<Locker>,
    pending_setup: Option<PendingSetup>,
    pending_rotation: Option<Key>,
    last_activity: Instant,
}

impl AppState {
    pub fn new(vault_path: PathBuf, device: DeviceKeyStore) -> Self {
        Self {
            vault_path,
            device,
            locker: None,
            pending_setup: None,
            pending_rotation: None,
            last_activity: Instant::now(),
        }
    }

    /// Records that the user is active, which postpones the auto-lock.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    fn locker(&self) -> AppResult<&Locker> {
        self.locker.as_ref().ok_or_else(AppError::locked)
    }

    fn locker_mut(&mut self) -> AppResult<&mut Locker> {
        self.locker.as_mut().ok_or_else(AppError::locked)
    }

    pub fn status(&self) -> Status {
        Status {
            vault_exists: self.vault_path.exists(),
            unlocked: self.locker.is_some(),
            vault_path: self.vault_path.display().to_string(),
            setup_pending: self.pending_setup.is_some(),
        }
    }

    // --- setup ---------------------------------------------------------

    /// Step one of creating a vault: checks the master password, makes the
    /// recovery key and returns its printable code. Nothing is written.
    pub fn begin_setup(&mut self, password: &str) -> AppResult<Zeroizing<String>> {
        if self.vault_path.exists() {
            return Err(AppError::new("a vault already exists"));
        }
        check_master_password(password)?;
        let recovery = Key::generate()?;
        let code = encode_recovery_code(&recovery);
        self.pending_setup = Some(PendingSetup {
            password: SecretString::new(password),
            recovery,
        });
        Ok(code)
    }

    /// Step two: the vault is created only if the typed code is the one that
    /// was shown. A wrong code keeps the pending setup so the user can retry.
    pub fn finish_setup(&mut self, typed_code: &str) -> AppResult<()> {
        let pending = self
            .pending_setup
            .as_ref()
            .ok_or_else(|| AppError::new("there is no setup in progress"))?;
        check_typed_code(typed_code, &pending.recovery)?;

        if let Some(dir) = self.vault_path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let device = self.device.load_or_create()?;
        let locker = Locker::create(
            &self.vault_path,
            pending.password.expose(),
            &device,
            &pending.recovery,
        )?;
        self.locker = Some(locker);
        self.pending_setup = None;
        self.touch();
        Ok(())
    }

    pub fn cancel_setup(&mut self) {
        self.pending_setup = None;
    }

    // --- unlocking -----------------------------------------------------

    pub fn unlock(&mut self, password: &str) -> AppResult<()> {
        let device = self.device.load()?.ok_or_else(|| {
            AppError::new(
                "this PC has no device key for the vault; unlock with your recovery code instead",
            )
        })?;
        let locker = Locker::open(&self.vault_path, password, FactorKind::Device, &device)?;
        self.locker = Some(locker);
        self.touch();
        Ok(())
    }

    /// Unlocks with the master password and the recovery code, then makes
    /// sure this PC can unlock normally next time.
    ///
    /// The recovery slot is opened first so that a wrong code is always
    /// caught. Then the device key is tried: if this PC already has a slot,
    /// adding another would only waste one of the few slots a vault has.
    pub fn unlock_with_recovery(&mut self, password: &str, code: &str) -> AppResult<()> {
        let recovery = decode_recovery_code(code)?;
        let mut locker = Locker::open(&self.vault_path, password, FactorKind::Recovery, &recovery)?;

        let device_already_works = match self.device.load() {
            Ok(Some(device)) => {
                Locker::open(&self.vault_path, password, FactorKind::Device, &device).is_ok()
            }
            _ => false,
        };
        if !device_already_works {
            // Failing to register this PC (for example when the vault has no
            // free slot) must not lock the user out of the session they just
            // unlocked, so it is not fatal.
            if let Ok(device) = self.device.load_or_create() {
                let _ = locker.add_device(&device);
            }
        }
        self.locker = Some(locker);
        self.touch();
        Ok(())
    }

    /// Drops the open vault. `Locker` wipes its keys and entries on drop.
    pub fn lock(&mut self) {
        self.locker = None;
        self.pending_rotation = None;
    }

    /// Used by the auto-lock thread. Locks if the session is locked or the
    /// user has been idle too long; returns whether it just locked.
    pub fn lock_if_needed(
        &mut self,
        now: Instant,
        idle_limit: Duration,
        session_locked: bool,
    ) -> bool {
        if self.locker.is_none() {
            return false;
        }
        let idle = now.saturating_duration_since(self.last_activity) > idle_limit;
        if idle || session_locked {
            self.lock();
            return true;
        }
        false
    }

    // --- entries -------------------------------------------------------

    pub fn list_entries(&mut self, query: &str) -> AppResult<Vec<EntrySummary>> {
        self.touch();
        let locker = self.locker()?;
        Ok(if query.trim().is_empty() {
            locker.summaries()
        } else {
            locker.search(query)
        })
    }

    pub fn add_entry(&mut self, input: DraftInput) -> AppResult<EntryId> {
        self.touch();
        let draft = EntryDraft {
            title: input.title,
            username: input.username,
            password: SecretString::new(input.password.unwrap_or_default()),
            url: input.url,
            notes: SecretString::new(input.notes.unwrap_or_default()),
            tags: input.tags,
        };
        Ok(self.locker_mut()?.add(draft)?)
    }

    pub fn update_entry(&mut self, id: &str, input: DraftInput) -> AppResult<()> {
        self.touch();
        let id = EntryId::parse(id)?;
        let locker = self.locker_mut()?;
        // `None` means "unchanged": fill in the stored value here, so the
        // window never has to fetch a secret it is not editing.
        let password = match input.password {
            Some(text) => SecretString::new(text),
            None => locker.password(&id)?.clone(),
        };
        let notes = match input.notes {
            Some(text) => SecretString::new(text),
            None => locker.notes(&id)?.clone(),
        };
        let draft = EntryDraft {
            title: input.title,
            username: input.username,
            password,
            url: input.url,
            notes,
            tags: input.tags,
        };
        Ok(locker.update(&id, draft)?)
    }

    pub fn delete_entry(&mut self, id: &str) -> AppResult<()> {
        self.touch();
        let id = EntryId::parse(id)?;
        Ok(self.locker_mut()?.delete(&id)?)
    }

    // --- secrets, one at a time -----------------------------------------

    pub fn reveal_password(&mut self, id: &str) -> AppResult<String> {
        self.touch();
        let id = EntryId::parse(id)?;
        Ok(self.locker()?.password(&id)?.expose().to_owned())
    }

    pub fn reveal_notes(&mut self, id: &str) -> AppResult<String> {
        self.touch();
        let id = EntryId::parse(id)?;
        Ok(self.locker()?.notes(&id)?.expose().to_owned())
    }

    pub fn reveal_password_history(&mut self, id: &str) -> AppResult<Vec<PastPasswordView>> {
        self.touch();
        let id = EntryId::parse(id)?;
        Ok(self
            .locker()?
            .password_history(&id)?
            .iter()
            .map(|past| PastPasswordView {
                password: past.password.expose().to_owned(),
                replaced_at: past.replaced_at,
            })
            .collect())
    }

    /// The password for the Rust-side clipboard code. It never goes to the
    /// window; the returned copy wipes itself when dropped.
    pub fn password_for_clipboard(&mut self, id: &str) -> AppResult<SecretString> {
        self.touch();
        let id = EntryId::parse(id)?;
        Ok(self.locker()?.password(&id)?.clone())
    }

    pub fn username(&mut self, id: &str) -> AppResult<String> {
        self.touch();
        let id = EntryId::parse(id)?;
        Ok(self.locker()?.summary(&id)?.username)
    }

    // --- generator -----------------------------------------------------

    pub fn generate_password(&mut self, options: &PasswordOptionsInput) -> AppResult<Generated> {
        self.touch();
        let options = CharOptions {
            length: options.length,
            lowercase: options.lowercase,
            uppercase: options.uppercase,
            digits: options.digits,
            symbols: options.symbols,
        };
        let text = generate_password(&options)?;
        Ok(Generated {
            text: text.expose().to_owned(),
            entropy_bits: options.entropy_bits(),
        })
    }

    pub fn generate_passphrase(&mut self, input: &PassphraseOptionsInput) -> AppResult<Generated> {
        self.touch();
        let mut options = PassphraseOptions {
            words: input.words,
            ..PassphraseOptions::default()
        };
        if let Some(separator) = &input.separator {
            options.separator = separator.clone();
        }
        let text = generate_passphrase(&options)?;
        Ok(Generated {
            text: text.expose().to_owned(),
            entropy_bits: options.entropy_bits(),
        })
    }

    // --- master password and recovery code -------------------------------

    pub fn change_master_password(&mut self, current: &str, new: &str) -> AppResult<()> {
        self.touch();
        Ok(self.locker_mut()?.change_password(current, new)?)
    }

    /// Step one of replacing the recovery code: makes a new key and returns
    /// its code. The vault is unchanged until [`finish_recovery_rotation`].
    pub fn begin_recovery_rotation(&mut self) -> AppResult<Zeroizing<String>> {
        self.touch();
        self.locker()?;
        let key = Key::generate()?;
        let code = encode_recovery_code(&key);
        self.pending_rotation = Some(key);
        Ok(code)
    }

    /// Step two: swaps the recovery key once the user typed the new code
    /// back correctly. The old code stops working.
    pub fn finish_recovery_rotation(&mut self, typed_code: &str) -> AppResult<()> {
        self.touch();
        let key = self
            .pending_rotation
            .as_ref()
            .ok_or_else(|| AppError::new("there is no recovery code change in progress"))?;
        check_typed_code(typed_code, key)?;
        let locker = self.locker.as_mut().ok_or_else(AppError::locked)?;
        locker.replace_recovery(key)?;
        self.pending_rotation = None;
        Ok(())
    }

    pub fn cancel_recovery_rotation(&mut self) {
        self.pending_rotation = None;
    }
}

/// Checks the code the user typed back against the key that was shown.
fn check_typed_code(typed: &str, expected: &Key) -> AppResult<()> {
    let typed = decode_recovery_code(typed)?;
    if typed.as_bytes() == expected.as_bytes() {
        Ok(())
    } else {
        Err(AppError::new(
            "that is a valid code, but not the one shown; check it against what you wrote down",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const PASSWORD: &str = "violet-anvil-quokka-drizzle-lantern-mosaic";
    const NEW_PASSWORD: &str = "tundra-biscuit-orbit-velvet-cobalt-nimbus";

    /// A vault in a temp dir plus helpers to act as "this PC" or "another PC".
    struct Fixture {
        dir: tempfile::TempDir,
        state: AppState,
        code: String,
    }

    impl Fixture {
        fn vault_path(dir: &Path) -> PathBuf {
            dir.join("Password Locker").join("vault.pwlk")
        }

        fn state_for_pc(&self, pc: &str) -> AppState {
            AppState::new(
                Self::vault_path(self.dir.path()),
                DeviceKeyStore::at(self.dir.path().join(pc).join("device.key")),
            )
        }

        /// Runs the whole setup flow and returns an unlocked state.
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let mut state = AppState::new(
                Self::vault_path(dir.path()),
                DeviceKeyStore::at(dir.path().join("pc1").join("device.key")),
            );
            let code = state.begin_setup(PASSWORD).unwrap().to_string();
            state.finish_setup(&code).unwrap();
            Self { dir, state, code }
        }
    }

    fn input(title: &str, password: Option<&str>, notes: Option<&str>) -> DraftInput {
        DraftInput {
            title: title.into(),
            username: "me".into(),
            password: password.map(Into::into),
            url: "https://example.com".into(),
            notes: notes.map(Into::into),
            tags: vec!["home".into()],
        }
    }

    #[test]
    fn setup_creates_the_vault_only_after_the_code_is_typed_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = Fixture::vault_path(dir.path());
        let mut state = AppState::new(
            path.clone(),
            DeviceKeyStore::at(dir.path().join("device.key")),
        );

        assert!(state.begin_setup("password123").is_err());
        assert!(!state.status().setup_pending);

        let code = state.begin_setup(PASSWORD).unwrap().to_string();
        assert!(state.status().setup_pending);
        assert!(!path.exists());

        // A syntactically valid code that is not the shown one, and garbage.
        let other = encode_recovery_code(&Key::generate().unwrap());
        assert!(state.finish_setup(&other).is_err());
        assert!(state.finish_setup("not a code").is_err());
        assert!(!path.exists());
        assert!(state.status().setup_pending);

        // Lower case and spaces are fine.
        state
            .finish_setup(&code.to_lowercase().replace('-', " "))
            .unwrap();
        let status = state.status();
        assert!(status.vault_exists && status.unlocked && !status.setup_pending);
        assert!(state.begin_setup(PASSWORD).is_err());
    }

    #[test]
    fn cancel_setup_forgets_the_pending_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = AppState::new(
            Fixture::vault_path(dir.path()),
            DeviceKeyStore::at(dir.path().join("device.key")),
        );
        let code = state.begin_setup(PASSWORD).unwrap().to_string();
        state.cancel_setup();
        assert!(state.finish_setup(&code).is_err());
    }

    #[test]
    fn lock_wipes_state_and_unlock_restores_it() {
        let mut f = Fixture::new();
        let id = f.state.add_entry(input("Mail", Some("pw1"), None)).unwrap();
        f.state.lock();

        assert!(!f.state.status().unlocked);
        assert!(f.state.list_entries("").is_err());
        assert!(f.state.reveal_password(id.as_str()).is_err());
        assert!(f.state.add_entry(input("X", None, None)).is_err());

        assert!(f.state.unlock("wrong password entirely").is_err());
        assert!(!f.state.status().unlocked);
        f.state.unlock(PASSWORD).unwrap();
        assert_eq!(f.state.reveal_password(id.as_str()).unwrap(), "pw1");
    }

    #[test]
    fn unlock_on_a_pc_without_a_device_key_points_to_the_recovery_code() {
        let f = Fixture::new();
        let mut other_pc = f.state_for_pc("pc2");
        let err = other_pc.unlock(PASSWORD).unwrap_err().to_string();
        assert!(err.contains("recovery code"));
    }

    #[test]
    fn unlocking_with_recovery_registers_this_pc() {
        let f = Fixture::new();
        let mut pc2 = f.state_for_pc("pc2");

        assert!(pc2.unlock_with_recovery(PASSWORD, "garbage").is_err());
        let wrong = encode_recovery_code(&Key::generate().unwrap());
        assert!(pc2.unlock_with_recovery(PASSWORD, &wrong).is_err());
        assert!(!pc2.status().unlocked);

        pc2.unlock_with_recovery(PASSWORD, &f.code).unwrap();
        assert!(pc2.status().unlocked);
        pc2.lock();
        // The device slot was added, so the normal unlock now works.
        pc2.unlock(PASSWORD).unwrap();
    }

    #[test]
    fn update_with_none_keeps_password_and_notes() {
        let mut f = Fixture::new();
        let id = f
            .state
            .add_entry(input("Mail", Some("pw1"), Some("note1")))
            .unwrap();
        let id = id.as_str();

        f.state
            .update_entry(id, input("Mail 2", None, None))
            .unwrap();
        assert_eq!(f.state.reveal_password(id).unwrap(), "pw1");
        assert_eq!(f.state.reveal_notes(id).unwrap(), "note1");
        assert_eq!(f.state.list_entries("").unwrap()[0].title, "Mail 2");
        assert!(f.state.reveal_password_history(id).unwrap().is_empty());

        f.state
            .update_entry(id, input("Mail 2", Some("pw2"), Some("")))
            .unwrap();
        assert_eq!(f.state.reveal_password(id).unwrap(), "pw2");
        assert_eq!(f.state.reveal_notes(id).unwrap(), "");
        let history = f.state.reveal_password_history(id).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].password, "pw1");

        f.state.delete_entry(id).unwrap();
        assert!(f.state.list_entries("").unwrap().is_empty());
        assert!(
            f.state
                .update_entry("nonsense", input("x", None, None))
                .is_err()
        );
    }

    #[test]
    fn listing_and_searching_never_include_secrets() {
        let mut f = Fixture::new();
        f.state
            .add_entry(input("Mail", Some("needle-pw"), Some("needle-note")))
            .unwrap();

        let all = f.state.list_entries("").unwrap();
        let json = serde_json::to_string(&all).unwrap();
        assert!(!json.contains("needle") && !json.contains("password"));
        assert!(json.contains("Mail") && json.contains("updated_at"));

        assert_eq!(f.state.list_entries("mail").unwrap().len(), 1);
        assert!(f.state.list_entries("needle").unwrap().is_empty());
        assert_eq!(f.state.username(all[0].id.as_str()).unwrap(), "me");
        assert_eq!(
            f.state
                .password_for_clipboard(all[0].id.as_str())
                .unwrap()
                .expose(),
            "needle-pw"
        );
    }

    #[test]
    fn recovery_rotation_replaces_the_old_code() {
        let mut f = Fixture::new();
        assert!(f.state.finish_recovery_rotation(&f.code).is_err());

        let new_code = f.state.begin_recovery_rotation().unwrap().to_string();
        assert!(f.state.finish_recovery_rotation(&f.code).is_err());
        f.state.finish_recovery_rotation(&new_code).unwrap();
        // Finishing consumed the pending key.
        assert!(f.state.finish_recovery_rotation(&new_code).is_err());

        let mut pc2 = f.state_for_pc("pc2");
        assert!(pc2.unlock_with_recovery(PASSWORD, &f.code).is_err());
        pc2.unlock_with_recovery(PASSWORD, &new_code).unwrap();
    }

    #[test]
    fn changing_the_master_password_needs_the_current_one() {
        let mut f = Fixture::new();
        assert!(
            f.state
                .change_master_password("not the current one", NEW_PASSWORD)
                .is_err()
        );
        assert!(
            f.state
                .change_master_password(PASSWORD, "password123")
                .is_err()
        );
        f.state
            .change_master_password(PASSWORD, NEW_PASSWORD)
            .unwrap();
        f.state.lock();
        assert!(f.state.unlock(PASSWORD).is_err());
        f.state.unlock(NEW_PASSWORD).unwrap();
    }

    #[test]
    fn auto_lock_after_idle_or_when_the_session_locks() {
        let mut f = Fixture::new();
        let now = Instant::now();

        assert!(!f.state.lock_if_needed(now, IDLE_LIMIT, false));
        assert!(f.state.status().unlocked);

        let later = now + IDLE_LIMIT + Duration::from_secs(1);
        assert!(f.state.lock_if_needed(later, IDLE_LIMIT, false));
        assert!(!f.state.status().unlocked);
        // Already locked: nothing to do, so no repeated event.
        assert!(!f.state.lock_if_needed(later, IDLE_LIMIT, true));

        f.state.unlock(PASSWORD).unwrap();
        assert!(f.state.lock_if_needed(Instant::now(), IDLE_LIMIT, true));
    }

    #[test]
    fn generators_report_entropy_and_validate() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = AppState::new(
            Fixture::vault_path(dir.path()),
            DeviceKeyStore::at(dir.path().join("device.key")),
        );
        let options = PasswordOptionsInput {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: false,
        };
        let generated = state.generate_password(&options).unwrap();
        assert_eq!(generated.text.chars().count(), 20);
        assert!(generated.entropy_bits > 100.0);
        let none = PasswordOptionsInput {
            lowercase: false,
            uppercase: false,
            digits: false,
            ..options
        };
        assert!(state.generate_password(&none).is_err());

        let phrase = state
            .generate_passphrase(&PassphraseOptionsInput {
                words: 4,
                separator: Some(" ".into()),
            })
            .unwrap();
        assert_eq!(phrase.text.split(' ').count(), 4);
        assert!((phrase.entropy_bits - 4.0 * 7776f64.log2()).abs() < 1e-9);
        assert!(
            state
                .generate_passphrase(&PassphraseOptionsInput {
                    words: 2,
                    separator: None
                })
                .is_err()
        );
    }
}

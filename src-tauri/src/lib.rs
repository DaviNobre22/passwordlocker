// The window may only call the commands registered in `run` below. Each one
// is a thin wrapper: the real work happens in `AppState` (see `app_state.rs`),
// which holds the unlocked vault and decides what may cross to the window.
//
// Security rules every command here follows:
// - errors are returned as the `Display` text of the core errors, which never
//   contain secrets;
// - secrets are returned only by the `reveal_*` commands and the generators.

mod app_state;
mod clipboard;
mod window;

use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use locker_core::EntrySummary;
use locker_device::DeviceKeyStore;
use tauri::{Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

use app_state::{
    AppState, DraftInput, Generated, IDLE_LIMIT, PassphraseOptionsInput, PasswordOptionsInput,
    PastPasswordView, Status, backup_file_name,
};

/// The one shared `AppState`. Commands run on different threads, so access
/// goes through a mutex.
type Shared<'a> = State<'a, Mutex<AppState>>;

/// How often the auto-lock thread looks at the clock and the Windows session.
const AUTO_LOCK_POLL: Duration = Duration::from_secs(5);

/// Locks the mutex, turning a poisoned one (a thread panicked while holding
/// it) into an error message instead of a second panic.
fn guard<'a>(state: &'a Shared<'_>) -> Result<MutexGuard<'a, AppState>, String> {
    state
        .lock()
        .map_err(|_| "internal error: the app state is unavailable".to_owned())
}

#[tauri::command]
fn status(state: Shared) -> Result<Status, String> {
    Ok(guard(&state)?.status())
}

#[tauri::command]
fn begin_setup(state: Shared, password: String) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let code = guard(&state)?
        .begin_setup(&password)
        .map_err(|e| e.to_string())?;
    // The recovery code is the one secret that must reach the window.
    Ok(code.to_string())
}

// `async` so that Tauri runs these on its thread pool instead of the thread
// that drives the window: key derivation takes about half a second. The
// mutex is held for that time (acceptable for v1: nothing else is useful
// while the vault is being opened or created).
#[tauri::command(async)]
fn finish_setup(state: Shared, typed_code: String) -> Result<(), String> {
    guard(&state)?
        .finish_setup(&typed_code)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn cancel_setup(state: Shared) -> Result<(), String> {
    guard(&state)?.cancel_setup();
    Ok(())
}

#[tauri::command(async)]
fn unlock(state: Shared, password: String) -> Result<(), String> {
    let password = Zeroizing::new(password);
    guard(&state)?.unlock(&password).map_err(|e| e.to_string())
}

#[tauri::command(async)]
fn unlock_with_recovery(state: Shared, password: String, code: String) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let code = Zeroizing::new(code);
    guard(&state)?
        .unlock_with_recovery(&password, &code)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn lock(state: Shared) -> Result<(), String> {
    guard(&state)?.lock();
    Ok(())
}

/// Called by the window while the user is active (typing, clicking), so a
/// long edit is not interrupted by the auto-lock.
#[tauri::command]
fn keep_alive(state: Shared) -> Result<(), String> {
    guard(&state)?.touch();
    Ok(())
}

#[tauri::command]
fn list_entries(state: Shared, query: String) -> Result<Vec<EntrySummary>, String> {
    guard(&state)?
        .list_entries(&query)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn add_entry(state: Shared, draft: DraftInput) -> Result<String, String> {
    let id = guard(&state)?.add_entry(draft).map_err(|e| e.to_string())?;
    Ok(id.as_str().to_owned())
}

#[tauri::command]
fn update_entry(state: Shared, id: String, draft: DraftInput) -> Result<(), String> {
    guard(&state)?
        .update_entry(&id, draft)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_entry(state: Shared, id: String) -> Result<(), String> {
    guard(&state)?.delete_entry(&id).map_err(|e| e.to_string())
}

#[tauri::command]
fn reveal_password(state: Shared, id: String) -> Result<String, String> {
    guard(&state)?
        .reveal_password(&id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn reveal_notes(state: Shared, id: String) -> Result<String, String> {
    guard(&state)?.reveal_notes(&id).map_err(|e| e.to_string())
}

#[tauri::command]
fn reveal_password_history(state: Shared, id: String) -> Result<Vec<PastPasswordView>, String> {
    guard(&state)?
        .reveal_password_history(&id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn copy_password(state: Shared, id: String) -> Result<(), String> {
    // The lock is released before touching the clipboard.
    let password = guard(&state)?
        .password_for_clipboard(&id)
        .map_err(|e| e.to_string())?;
    clipboard::copy_password(password.expose())
}

#[tauri::command]
fn copy_username(state: Shared, id: String) -> Result<(), String> {
    let username = guard(&state)?.username(&id).map_err(|e| e.to_string())?;
    clipboard::copy_text(&username)
}

#[tauri::command]
fn generate_password(state: Shared, options: PasswordOptionsInput) -> Result<Generated, String> {
    guard(&state)?
        .generate_password(&options)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn generate_passphrase(
    state: Shared,
    options: PassphraseOptionsInput,
) -> Result<Generated, String> {
    guard(&state)?
        .generate_passphrase(&options)
        .map_err(|e| e.to_string())
}

#[tauri::command(async)]
fn change_master_password(
    state: Shared,
    current: String,
    new_password: String,
) -> Result<(), String> {
    let current = Zeroizing::new(current);
    let new_password = Zeroizing::new(new_password);
    guard(&state)?
        .change_master_password(&current, &new_password)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn begin_recovery_rotation(state: Shared) -> Result<String, String> {
    let code = guard(&state)?
        .begin_recovery_rotation()
        .map_err(|e| e.to_string())?;
    Ok(code.to_string())
}

#[tauri::command(async)]
fn finish_recovery_rotation(state: Shared, typed_code: String) -> Result<(), String> {
    guard(&state)?
        .finish_recovery_rotation(&typed_code)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn cancel_recovery_rotation(state: Shared) -> Result<(), String> {
    guard(&state)?.cancel_recovery_rotation();
    Ok(())
}

/// Seconds since 1970, for the suggested backup file name.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

// The commands below show a native file dialog. The dialog plugin is used
// from Rust only: the window has no permission for the plugin's own
// commands (see `capabilities/default.json`), so it can open no dialog and
// pick no path itself. They are `async` so Tauri runs them off the thread
// that drives the window, which a blocking dialog would freeze. The
// `AppState` mutex is never held while a dialog is open, or the auto-lock
// thread and every other command would wait for the user.

/// Asks where to save a copy of the encrypted vault, then writes it.
/// Returns the chosen path, or `None` if the user closed the dialog.
#[tauri::command(async)]
fn export_backup(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    state: Shared,
) -> Result<Option<String>, String> {
    guard(&state)?
        .ensure_unlocked()
        .map_err(|e| e.to_string())?;
    let picked = app
        .dialog()
        .file()
        .set_parent(&window)
        .add_filter("Password Locker vault", &["pwlk"])
        .set_file_name(backup_file_name(unix_now()))
        .blocking_save_file();
    let Some(picked) = picked else {
        return Ok(None);
    };
    let dest = picked.into_path().map_err(|e| e.to_string())?;
    guard(&state)?
        .export_backup_to(&dest)
        .map_err(|e| e.to_string())?;
    Ok(Some(dest.display().to_string()))
}

/// Asks which backup file to restore from and remembers it in Rust. Returns
/// the path for display, or `None` if the user closed the dialog.
#[tauri::command(async)]
fn pick_backup_file(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    state: Shared,
) -> Result<Option<String>, String> {
    let picked = app
        .dialog()
        .file()
        .set_parent(&window)
        .add_filter("Password Locker vault", &["pwlk"])
        .blocking_pick_file();
    let Some(picked) = picked else {
        return Ok(None);
    };
    let source = picked.into_path().map_err(|e| e.to_string())?;
    let shown = source.display().to_string();
    guard(&state)?
        .set_restore_source(source)
        .map_err(|e| e.to_string())?;
    Ok(Some(shown))
}

/// Replaces the vault with the picked backup. `password` and `code` belong
/// to the backup. On success the vault is open.
#[tauri::command(async)]
fn restore_backup(state: Shared, password: String, code: String) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let code = Zeroizing::new(code);
    guard(&state)?
        .restore_backup(&password, &code)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn cancel_restore(state: Shared) -> Result<(), String> {
    guard(&state)?.cancel_restore();
    Ok(())
}

/// Runs for the life of the app: locks the vault after [`IDLE_LIMIT`] without
/// activity or when Windows locks the session, and tells the window.
fn spawn_auto_lock(app: tauri::AppHandle) {
    thread::spawn(move || {
        loop {
            thread::sleep(AUTO_LOCK_POLL);
            let session_locked = locker_device::is_session_locked();
            let state = app.state::<Mutex<AppState>>();
            let locked_now = match state.lock() {
                Ok(mut state) => state.lock_if_needed(Instant::now(), IDLE_LIMIT, session_locked),
                Err(_) => false,
            };
            if locked_now {
                let _ = app.emit("vault-locked", ());
            }
        }
    });
}

/// Development builds can keep the vault and device key in a throwaway
/// folder named by `PASSWORDLOCKER_DEV_DIR`, so trying the app never touches
/// the real ones. Release builds ignore the variable entirely.
#[cfg(debug_assertions)]
fn dev_data_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("PASSWORDLOCKER_DEV_DIR").map(std::path::PathBuf::from)
}

#[cfg(not(debug_assertions))]
fn dev_data_dir() -> Option<std::path::PathBuf> {
    None
}

pub fn run() {
    tauri::Builder::default()
        // Must be the first plugin. Two copies of the app writing the same
        // vault would lose changes, so a second start only brings the
        // running window to the front and exits.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            window::focus_main_window(app);
        }))
        // Used from Rust only (the file dialogs above); no window permission.
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            window::create_main_window(app)?;
            let (vault_path, device) = match dev_data_dir() {
                Some(dir) => (
                    dir.join("vault.pwlk"),
                    DeviceKeyStore::at(dir.join("device.key")),
                ),
                None => (
                    // `document_dir` follows the real Documents folder,
                    // including when Windows has redirected it (for example
                    // to OneDrive).
                    app.path()
                        .document_dir()?
                        .join("Password Locker")
                        .join("vault.pwlk"),
                    DeviceKeyStore::default_location()?,
                ),
            };
            app.manage(Mutex::new(AppState::new(vault_path, device)));
            spawn_auto_lock(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status,
            begin_setup,
            finish_setup,
            cancel_setup,
            unlock,
            unlock_with_recovery,
            lock,
            keep_alive,
            list_entries,
            add_entry,
            update_entry,
            delete_entry,
            reveal_password,
            reveal_notes,
            reveal_password_history,
            copy_password,
            copy_username,
            generate_password,
            generate_passphrase,
            change_master_password,
            begin_recovery_rotation,
            finish_recovery_rotation,
            cancel_recovery_rotation,
            export_backup,
            pick_backup_file,
            restore_backup,
            cancel_restore,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

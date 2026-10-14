//! The system clipboard, written from Rust so a copied password never has to
//! pass through the window.

use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use arboard::Clipboard;
use zeroize::Zeroizing;

/// How long a copied password stays on the clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(30);

/// Counts password copies. Each clearing thread remembers its number and
/// does nothing if a newer copy was made meanwhile, so copying the same
/// password twice is not cut short by the first timer.
static LATEST_COPY: AtomicU64 = AtomicU64::new(0);

/// Puts plain text (a username) on the clipboard.
pub fn copy_text(text: &str) -> Result<(), String> {
    let mut clipboard = open()?;
    clipboard.set_text(text).map_err(clipboard_error)
}

/// Puts a password on the clipboard and clears it again after
/// [`CLEAR_AFTER`], but only if the clipboard still holds that password.
pub fn copy_password(password: &str) -> Result<(), String> {
    let mut clipboard = open()?;
    set_sensitive(&mut clipboard, password)?;

    let copy_number = LATEST_COPY.fetch_add(1, Ordering::SeqCst) + 1;
    // The thread needs its own copy; it is wiped when the thread ends.
    let expected = Zeroizing::new(password.to_owned());
    thread::spawn(move || {
        thread::sleep(CLEAR_AFTER);
        if LATEST_COPY.load(Ordering::SeqCst) != copy_number {
            return;
        }
        let Ok(mut clipboard) = Clipboard::new() else {
            return;
        };
        // If the user copied something else, leave it alone.
        let still_ours = clipboard
            .get_text()
            .map(|current| *Zeroizing::new(current) == *expected)
            .unwrap_or(false);
        if still_ours {
            let _ = clipboard.clear();
        }
    });
    Ok(())
}

/// On Windows, asks to keep the text out of Win+V clipboard history, out of
/// the cloud clipboard and away from clipboard-monitoring tools.
#[cfg(windows)]
fn set_sensitive(clipboard: &mut Clipboard, text: &str) -> Result<(), String> {
    use arboard::SetExtWindows;
    clipboard
        .set()
        .exclude_from_history()
        .exclude_from_cloud()
        .exclude_from_monitoring()
        .text(text)
        .map_err(clipboard_error)
}

#[cfg(not(windows))]
fn set_sensitive(clipboard: &mut Clipboard, text: &str) -> Result<(), String> {
    clipboard.set_text(text).map_err(clipboard_error)
}

fn open() -> Result<Clipboard, String> {
    Clipboard::new().map_err(clipboard_error)
}

fn clipboard_error(err: arboard::Error) -> String {
    format!("the clipboard is not available: {err}")
}

//! The main window and the rules that keep it on the app's own page.
//!
//! The window shows our own files and nothing else. If it could be sent to
//! another page (by a link, a redirect or a script), that page would run
//! next to the commands that reach the vault. So every navigation is checked
//! here, and no link may open a new window.

use tauri::webview::{NewWindowResponse, WebviewWindowBuilder};
use tauri::{App, AppHandle, Manager, Url, WebviewWindow};

/// Label of the one window; `capabilities/default.json` names it too.
pub const MAIN_LABEL: &str = "main";

/// Whether the window may load `url`.
///
/// The app's own pages are served from `tauri://localhost` (and from
/// `http://tauri.localhost` on Windows). A development build also loads
/// Vite's server at `http://localhost:1420`. Everything else is refused,
/// including `file:`, `data:`, `about:` and any web address.
pub fn is_allowed_navigation(url: &Url) -> bool {
    let origin = (url.scheme(), url.host_str(), url.port());
    matches!(
        origin,
        ("tauri", Some("localhost"), None) | ("http", Some("tauri.localhost"), None)
    ) || (cfg!(debug_assertions) && origin == ("http", Some("localhost"), Some(1420)))
}

/// Creates the main window from `tauri.conf.json` (which sets `create:
/// false`, so Tauri does not make an unguarded one) with the navigation
/// rules attached.
pub fn create_main_window(app: &App) -> tauri::Result<WebviewWindow> {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|window| window.label == MAIN_LABEL)
        .ok_or(tauri::Error::WindowNotFound)?;
    WebviewWindowBuilder::from_config(app.handle(), config)?
        .on_navigation(is_allowed_navigation)
        // `window.open` and `target="_blank"` links open nothing.
        .on_new_window(|_url, _features| NewWindowResponse::Deny)
        .build()
}

/// Brings the window to the front, for when a second copy of the app is
/// started. Failures are ignored: there is nothing useful to do about them.
pub fn focus_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_LABEL) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(url: &str) -> bool {
        is_allowed_navigation(&Url::parse(url).unwrap())
    }

    #[test]
    fn only_the_apps_own_origins_are_allowed() {
        assert!(allowed("tauri://localhost/index.html"));
        assert!(allowed("http://tauri.localhost/"));
        assert!(allowed("http://tauri.localhost/assets/app.js"));

        assert!(!allowed("https://example.com/"));
        assert!(!allowed("http://example.com/"));
        // Look-alike hosts and other schemes.
        assert!(!allowed("http://tauri.localhost.evil.test/"));
        assert!(!allowed("http://evil.test/tauri.localhost"));
        assert!(!allowed("https://tauri.localhost/"));
        assert!(!allowed("tauri://evil/"));
        assert!(!allowed("file:///C:/Windows/win.ini"));
        assert!(!allowed("data:text/html,hello"));
        assert!(!allowed("about:blank"));
        assert!(!allowed("http://localhost:8080/"));
    }

    #[test]
    fn the_dev_server_is_allowed_only_in_debug_builds() {
        assert_eq!(allowed("http://localhost:1420/"), cfg!(debug_assertions));
    }
}

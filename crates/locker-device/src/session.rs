//! Detects whether the Windows session is locked (Win+L, lock screen).
//!
//! While the workstation is locked, the secure desktop is the input desktop
//! and an ordinary program is not allowed to open it. That refusal is the
//! signal: `OpenInputDesktop` fails with access denied (returns null).

#[cfg(windows)]
pub fn is_session_locked() -> bool {
    use windows_sys::Win32::System::StationsAndDesktops::{
        CloseDesktop, DESKTOP_SWITCHDESKTOP, OpenInputDesktop,
    };

    // SAFETY: all arguments are plain values. A non-null handle returned by
    // `OpenInputDesktop` is ours alone and is closed exactly once below.
    let desktop = unsafe { OpenInputDesktop(0, 0, DESKTOP_SWITCHDESKTOP) };
    if desktop.is_null() {
        return true;
    }
    // SAFETY: `desktop` is a valid handle from the call above, not used again.
    unsafe { CloseDesktop(desktop) };
    false
}

#[cfg(not(windows))]
pub fn is_session_locked() -> bool {
    false
}

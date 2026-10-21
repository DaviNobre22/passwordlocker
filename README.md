
# passwordlocker

A personal password manager for Windows. It keeps your logins in one encrypted file on your PC. It has no account, no cloud and no network access.

## Where things are stored

| What | Where |
| --- | --- |
| Your vault | `Documents\Password Locker\vault.pwlk` |
| Rolling backups | `vault.pwlk.bak.1` to `.bak.5`, next to the vault. `.bak.1` is the version before the last change. |
| This PC's device key | `%LOCALAPPDATA%\passwordlocker\device.key` |

The device key is deliberately not in Documents, so it does not travel with the vault if that folder is synced or copied.

The `.bak.N` files are not an off-PC backup: they sit in the same folder as the vault. Make an export (below) and keep it somewhere else.

## How unlocking works

Opening the vault needs two things:

1. your master password, and
2. a second factor: this PC's device key, which Windows protects for your user account, or the recovery code.

On your own PC the device key is used automatically, so you only type the master password. The vault file on its own, or copied to another PC, cannot be opened without both.

The vault locks itself after 5 minutes without use and when Windows locks.

The recovery code is shown once when you create the vault. Write it down and keep it on paper, away from the PC. You can make a new one in Settings (the old one then stops working).

## Backing up and restoring

**Export.** Settings, "Export backup...". You choose where to save a `.pwlk` file, for example a USB stick. The file is the encrypted vault itself. On another PC it opens with your master password and your recovery code.

**Restore.** On the first-run screen choose "Restore from a backup file instead", or use Settings, "Restore from a backup file...". Pick the file, then enter the master password and recovery code that belong to that backup (they may be older than your current ones). Restoring over an existing vault replaces it, after saving a copy next to it called `vault.pwlk.before-restore-<number>`. The restore also registers this PC's device key, so afterwards you unlock normally.

## Using it on a new PC

1. Install the app and start it.
2. Choose "Restore from a backup file instead" and pick your exported file, or copy `vault.pwlk` to `Documents\Password Locker` and choose "Use recovery code instead" on the unlock screen.
3. Enter your master password and your recovery code.

This PC is then registered, and from now on the master password is enough here.

## Trial plan

Keep using your current password manager in parallel until export and restore have been tested on a second machine or a VM. Do not rely on this app alone before you have seen a backup open somewhere else.

## Security model

What it protects against:

- Someone who gets a copy of the vault file (a stolen disk, a leaked backup, a synced folder): they still need the master password and either this PC's device key or the recovery code.
- Guessing the master password offline: it goes through Argon2id, and a weak one is refused when you set it.
- Passwords lingering: they are copied to the clipboard only when you ask, and the clipboard is cleared after 30 seconds.

What it does not protect against:

- Malware or another person running as your Windows user while the vault is unlocked. It can read what the app can read.
- Someone who has both your master password and your unlocked Windows account or recovery code.
- A rolled-back vault file. If an old copy replaces the file, the app cannot tell, and recent changes are lost.
- A forgotten master password. The recovery code does not replace it. Without the password the data cannot be recovered by anyone.

## Development

```sh
npm install          # once
npm run tauri dev    # run the app
npm run test:core    # test the core
cargo test --workspace  # test everything
npm run lint:rust    # format check and clippy
npm run build        # type-check and build the window
npm run tauri build  # build the installer
```

In debug builds, set `PASSWORDLOCKER_DEV_DIR` to a folder to keep the vault and device key there instead of the real locations, so trying things never touches your data. Release builds ignore it.

```powershell
$env:PASSWORDLOCKER_DEV_DIR = "C:\temp\pwl-dev"
npm run tauri dev
```

Layout:

- `crates/locker-core`: vault format, crypto and entry logic. No UI.
- `crates/locker-device`: the device key, protected with Windows DPAPI.
- `src-tauri`: the desktop app. Exposes a small set of commands to the window.
- `src`: the window, in React and TypeScript.

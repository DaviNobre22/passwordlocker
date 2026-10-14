<img src="assets/icon.svg" width="64" height="64" alt="">

# passwordlocker

A personal password manager for Windows, built with Tauri.

## Layout

- `crates/locker-core`: vault format, crypto and entry logic. No UI.
- `src-tauri`: the desktop app. Exposes a small set of commands to the window.
- `src`: the window, in React and TypeScript.

## Commands

```sh
npm install          # once
npm run tauri dev    # run the app
npm run test:core    # test the core
npm run lint:rust    # format check and clippy
npm run tauri build  # build the installer
```

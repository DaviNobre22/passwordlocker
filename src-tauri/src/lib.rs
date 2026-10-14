// The window may only call the commands registered in `run` below. Each one
// is a thin wrapper: the real work happens in `locker_core`.

#[tauri::command]
fn core_version() -> &'static str {
    locker_core::version()
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![core_version])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

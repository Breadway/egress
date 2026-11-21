use std::path::PathBuf;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconEvent;
use tauri::{Manager, WindowEvent};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![api_token])
        .setup(|app| {
            let show = MenuItem::with_id(app, "show", "Open egress", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;

            let tray = app
                .tray_by_id("main")
                .ok_or_else(|| "tray icon is not configured".to_string())?;
            tray.set_menu(Some(menu))?;
            tray.on_menu_event(|app, event| match event.id.as_ref() {
                "show" => reveal(app),
                "quit" => app.exit(0),
                _ => {}
            });
            tray.on_tray_icon_event(|tray, event| {
                if let TrayIconEvent::DoubleClick { .. } = event {
                    reveal(tray.app_handle());
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps the tray icon and the app running. The
            // daemon owns the tunnel, so hiding the UI never drops protection.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running egress");
}

fn reveal(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

// api_token hands the webview the bearer token the daemon writes for the
// signed-in user. The file is loopback-scoped; the webview never sees any
// other daemon state.
#[tauri::command]
fn api_token() -> Result<String, String> {
    let path = std::env::var("EGRESS_API_TOKEN_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_token_path());
    let raw = std::fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))?;
    let token = raw.trim().to_string();
    if token.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(token)
}

// default_token_path must match internal/egress/api_token_path.go: the runtime
// directory on Linux, ProgramData\egress-gui on Windows, and the local var run
// directory on macOS. The daemon runs elevated, so none of these may be the
// user's temp directory.
fn default_token_path() -> PathBuf {
    match std::env::consts::OS {
        "linux" => PathBuf::from("/run/egress/api-token"),
        "windows" => {
            let base =
                std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
            PathBuf::from(base).join("egress-gui").join("api-token")
        }
        _ => PathBuf::from("/usr/local/var/run/egress/api-token"),
    }
}

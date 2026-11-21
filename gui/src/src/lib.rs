use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconEvent;
use tauri::{Manager, WindowEvent};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
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
        .unwrap_or_else(|_| "/run/egress/api-token".to_string());
    let raw = std::fs::read_to_string(&path).map_err(|err| format!("{path}: {err}"))?;
    let token = raw.trim().to_string();
    if token.is_empty() {
        return Err(format!("{path} is empty"));
    }
    Ok(token)
}

use std::path::PathBuf;
use std::sync::Mutex;

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager, WindowEvent};

struct TrayState {
    connected: bool,
    label: String,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let start_hidden = std::env::args().any(|arg| arg == "--tray");
    tauri::Builder::default()
        // Registered first so a second launch is handed to this instance
        // before anything else starts a window or a tray icon.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            reveal(app);
        }))
        .plugin(tauri_plugin_notification::init())
        .manage(Mutex::new(TrayState {
            connected: false,
            label: "egress".to_string(),
        }))
        .invoke_handler(tauri::generate_handler![api_token, set_tray_state])
        .setup(move |app| {
            let menu = tray_menu(app.handle(), false, "egress")?;
            // Build the icon here from an embedded transparent PNG. Relying on
            // the config path alone made the dark app tile invisible on a
            // dark Linux bar, and a missing runtime file leaves no tray at all.
            let icon = Image::from_bytes(include_bytes!("../icons/tray.png"))?;
            let tray = TrayIconBuilder::with_id("main")
                .icon(icon)
                .tooltip("egress")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => reveal(app),
                    "hide" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.hide();
                        }
                    }
                    "toggle" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.emit("tray-toggle", ());
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::DoubleClick { .. } = event {
                        reveal(tray.app_handle());
                    }
                })
                .build(app)?;
            let _ = tray;

            if !start_hidden {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window quits the app. The daemon owns the tunnel,
            // so protection is unaffected, and a closed app should not leave
            // an invisible process behind. Use the tray's Hide item when you
            // want the app to keep running.
            if let WindowEvent::CloseRequested { .. } = event {
                window.app_handle().exit(0);
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running egress");
}

fn tray_menu<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    connected: bool,
    label: &str,
) -> tauri::Result<Menu<R>> {
    let status = MenuItem::with_id(app, "status", label, false, None::<&str>)?;
    let open = MenuItem::with_id(app, "show", "Open egress", true, None::<&str>)?;
    let hide = MenuItem::with_id(app, "hide", "Hide to tray", true, None::<&str>)?;
    let toggle = MenuItem::with_id(
        app,
        "toggle",
        if connected { "Disconnect" } else { "Connect" },
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    Menu::with_items(app, &[&status, &open, &hide, &toggle, &quit])
}

// set_tray_state keeps the tray menu in step with the live connection. The
// frontend calls it whenever status changes.
#[tauri::command]
fn set_tray_state(
    app: tauri::AppHandle,
    state: tauri::State<'_, Mutex<TrayState>>,
    connected: bool,
    label: String,
) -> Result<(), String> {
    {
        let mut current = state
            .lock()
            .map_err(|_| "tray state is poisoned".to_string())?;
        current.connected = connected;
        current.label = label.clone();
    }
    let menu = tray_menu(&app, connected, &label).map_err(|err| err.to_string())?;
    if let Some(tray) = app.tray_by_id("main") {
        tray.set_menu(Some(menu)).map_err(|err| err.to_string())?;
    }
    Ok(())
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

use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconEvent;
use tauri::{Manager, WindowEvent};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
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

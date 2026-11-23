// setTrayState keeps the desktop tray menu in step with the connection. It is
// a no-op in a plain browser.
export async function setTrayState(connected: boolean, label: string): Promise<void> {
  if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) return;
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("set_tray_state", { connected, label });
  } catch {
    // A missing tray host must not break the app.
  }
}

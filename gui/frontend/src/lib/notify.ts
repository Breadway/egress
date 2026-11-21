// notify raises a native desktop notification from the Tauri shell. In a plain
// browser (development) it is a no-op.
let granted: boolean | null = null;

function available(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export async function notify(title: string, body: string): Promise<void> {
  if (!available()) return;
  try {
    const plugin = await import("@tauri-apps/plugin-notification");
    if (granted === null) {
      granted = await plugin.isPermissionGranted();
      if (!granted) {
        granted = (await plugin.requestPermission()) === "granted";
      }
    }
    if (granted) {
      plugin.sendNotification({ title, body });
    }
  } catch {
    // A desktop without a notification service should not break the app.
  }
}

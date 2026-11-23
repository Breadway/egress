<script lang="ts">
  import { app } from "$lib/state/app.svelte";
  import { toast } from "$lib/state/toast.svelte";
  import { setTrayState } from "$lib/tray";
  import IconSprite from "$lib/components/IconSprite.svelte";
  import Sidebar from "$lib/components/Sidebar.svelte";
  import Statusbar from "$lib/components/Statusbar.svelte";
  import Topbar from "$lib/components/Topbar.svelte";
  import ToastHost from "$lib/components/ToastHost.svelte";
  import "$lib/theme.css";

  let { children } = $props();

  app.start();

  // The text size setting uses rem sizes, so moving the root font size is
  // enough to scale every label without touching each component.
  $effect(() => {
    if (typeof document !== "undefined") {
      document.documentElement.dataset.textSize = app.settings.text_size;
    }
  });

  $effect(() => {
    const label = app.connected ? `Protected · ${app.routeLabel}` : "Disconnected";
    void setTrayState(app.connected, label);
  });

  $effect(() => {
    if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) return;
    let active = true;
    let unlisten: (() => void) | undefined;
    import("@tauri-apps/api/event")
      .then(({ listen }) =>
        listen("tray-toggle", async () => {
          try {
            const connected = await app.toggle();
            toast.show(
              connected
                ? "Reconnected. You are protected again"
                : "Disconnected. Your normal connection is back"
            );
          } catch (err) {
            toast.show(err instanceof Error ? err.message : "Could not change the connection");
          }
        })
      )
      .then((stop) => {
        if (active) unlisten = stop;
        else stop();
      })
      .catch(() => {});
    return () => {
      active = false;
      unlisten?.();
    };
  });
</script>

<IconSprite />

<div class="app">
  <Sidebar />
  <main class="main">
    <Topbar />
    <div class="scroll">
      {@render children()}
    </div>
    <Statusbar />
  </main>
</div>

<ToastHost />

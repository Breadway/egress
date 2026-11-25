<script lang="ts">
  import { page } from "$app/stores";
  import Icon from "$lib/components/Icon.svelte";
  import { admin } from "$lib/state/admin.svelte";
  import { app } from "$lib/state/app.svelte";
  import { toast } from "$lib/state/toast.svelte";

  const pages: Record<string, [string, string]> = {
    "/": ["Home", "Your private connection at a glance."],
    "/friends": ["Friends", "People and devices in your circle."],
    "/protection": ["Protection", "Sites egress has unblocked for you."],
    "/activity": ["Activity", "What happened on your connection."],
    "/settings": ["Settings", "Connection, sharing and privacy."],
    "/admin": ["Admin", "Applications, devices and invites."],
    "/admin/applications": ["Applications", "Approve, reissue and remove requests."],
    "/admin/devices": ["Devices", "Invites and installed devices."]
  };

  let meta = $derived(pages[$page.url.pathname] ?? pages["/"]);

  async function toggleConnection() {
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
  }

  async function refresh() {
    if ($page.url.pathname.startsWith("/admin")) {
      await admin.load();
      toast.show(admin.error ?? "Admin data refreshed");
      return;
    }
    try {
      await app.refreshAll();
      toast.show("Updated");
    } catch (err) {
      toast.show(err instanceof Error ? err.message : "Could not reach the egress service");
    }
  }
</script>

<header class="topbar">
  <div>
    <h1>{meta[0]}</h1>
    <p>{meta[1]}</p>
  </div>
  <div class="top-actions">
    <button class="btn ghost" onclick={refresh}>
      <Icon name="refresh" cls="sm" /> Refresh
    </button>
    <button class="btn primary" onclick={toggleConnection}>
      <Icon name="power" cls="sm" /> {app.connected ? "Disconnect" : "Connect"}
    </button>
  </div>
</header>

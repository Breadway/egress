<script lang="ts">
  import { page } from "$app/stores";
  import Icon from "$lib/components/Icon.svelte";
  import { app } from "$lib/state/app.svelte";
  import { toast } from "$lib/state/toast.svelte";

  const pages: Record<string, [string, string]> = {
    "/": ["Home", "Your private connection at a glance."],
    "/friends": ["Friends", "People and devices in your circle."],
    "/protection": ["Protection", "Sites egress has unblocked for you."],
    "/activity": ["Activity", "What happened on your connection."],
    "/settings": ["Settings", "Connection, sharing and privacy."]
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

  function testConnection() {
    if (!app.live) {
      toast.show("Showing demo data. Start the egress service to test");
      return;
    }
    toast.show(
      app.connected
        ? `Everything looks good. ${app.speed.toFixed(1)} Mbps right now`
        : "The connection is paused"
    );
  }
</script>

<header class="topbar">
  <div>
    <h1>{meta[0]}</h1>
    <p>{meta[1]}</p>
  </div>
  <div class="top-actions">
    <button class="btn ghost" onclick={testConnection}>
      <Icon name="bolt" cls="sm" /> Test connection
    </button>
    <button class="btn primary" onclick={toggleConnection}>
      <Icon name="power" cls="sm" /> {app.connected ? "Disconnect" : "Connect"}
    </button>
  </div>
</header>

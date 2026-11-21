<script lang="ts">
  import { page } from "$app/stores";
  import Icon from "$lib/components/Icon.svelte";
  import { connection } from "$lib/state/connection.svelte";
  import { toast } from "$lib/state/toast.svelte";

  const pages: Record<string, [string, string]> = {
    "/": ["Home", "Your private connection at a glance."],
    "/friends": ["Friends", "People and devices in your circle."],
    "/protection": ["Protection", "Sites egress has unblocked for you."],
    "/activity": ["Activity", "What happened on your connection."],
    "/settings": ["Settings", "Connection, sharing and privacy."]
  };

  let meta = $derived(pages[$page.url.pathname] ?? pages["/"]);

  function toggleConnection() {
    connection.toggle();
    toast.show(
      connection.connected
        ? "Reconnected. You are protected again"
        : "Disconnected. Your normal connection is back"
    );
  }
</script>

<header class="topbar">
  <div>
    <h1>{meta[0]}</h1>
    <p>{meta[1]}</p>
  </div>
  <div class="top-actions">
    <button class="btn ghost" onclick={() => toast.show("Everything looks good. Direct 18 ms, relay 54 ms")}>
      <Icon name="bolt" cls="sm" /> Test connection
    </button>
    <button class="btn primary" onclick={toggleConnection}>
      <Icon name="power" cls="sm" /> {connection.connected ? "Disconnect" : "Connect"}
    </button>
  </div>
</header>

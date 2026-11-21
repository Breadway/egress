<script lang="ts">
  import { browser } from "$app/environment";
  import "$lib/theme.css";
  import IconSprite from "$lib/components/IconSprite.svelte";
  import Sidebar from "$lib/components/Sidebar.svelte";
  import Statusbar from "$lib/components/Statusbar.svelte";
  import Topbar from "$lib/components/Topbar.svelte";
  import ToastHost from "$lib/components/ToastHost.svelte";
  import { connection } from "$lib/state/connection.svelte";

  let { children } = $props();

  // A little life in the speed figure, matching the mockup. It stops while the
  // connection is off and when reduced motion is requested.
  $effect(() => {
    if (!browser) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const timer = setInterval(() => {
      if (!connection.connected) return;
      const next = connection.speed + (Math.random() - 0.5) * 0.5;
      connection.speed = Math.min(21.2, Math.max(18.9, next));
    }, 2400);
    return () => clearInterval(timer);
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

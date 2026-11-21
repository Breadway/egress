<script lang="ts">
  import IconSprite from "$lib/components/IconSprite.svelte";
  import Sidebar from "$lib/components/Sidebar.svelte";
  import Statusbar from "$lib/components/Statusbar.svelte";
  import Topbar from "$lib/components/Topbar.svelte";
  import ToastHost from "$lib/components/ToastHost.svelte";
  import { app } from "$lib/state/app.svelte";
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

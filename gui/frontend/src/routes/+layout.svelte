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

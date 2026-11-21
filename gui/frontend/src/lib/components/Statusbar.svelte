<script lang="ts">
  import Icon from "$lib/components/Icon.svelte";
  import { app } from "$lib/state/app.svelte";
</script>

<footer class="statusbar">
  <span class="item"><i class="dot" class:off={!app.connected}></i> {app.statusLabel}</span>
  <span class="item"><Icon name="shield" cls="sm" /> {app.unblocked} sites unblocked today</span>
  <span class="item"><Icon name="globe" cls="sm" /> {app.dataGb.toFixed(1)} GB used</span>
  <div class="right">
    <span>{app.duration}</span>
    <span>{app.mode === "automatic" ? "Smart routing" : app.modeLabel}</span>
    <span class="mono">{app.version}</span>
  </div>
</footer>

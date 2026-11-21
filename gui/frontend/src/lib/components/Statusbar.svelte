<script lang="ts">
  import Icon from "$lib/components/Icon.svelte";
  import { connection } from "$lib/state/connection.svelte";
</script>

<footer class="statusbar">
  <span class="item"><i class="dot" class:off={!connection.connected}></i> {connection.statusLabel}</span>
  <span class="item"><Icon name="shield" cls="sm" /> {connection.unblocked} sites unblocked today</span>
  <span class="item"><Icon name="globe" cls="sm" /> {connection.dataGb} GB used</span>
  <div class="right">
    <span>3h 12m</span>
    <span>{connection.mode === "automatic" ? "Smart routing" : connection.modeLabel}</span>
    <span class="mono">{connection.version}</span>
  </div>
</footer>

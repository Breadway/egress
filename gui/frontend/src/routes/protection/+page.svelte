<script lang="ts">
  import type { Site } from "$lib/api/types";
  import Icon from "$lib/components/Icon.svelte";
  import { protectionStats, sites } from "$lib/data/mock";
  import { toast } from "$lib/state/toast.svelte";

  type Filter = "all" | "hestia" | "cloud" | "retry";

  let query = $state("");
  let filter = $state<Filter>("all");

  const visible = $derived(
    sites.filter((site) => {
      if (filter === "hestia" && site.via !== "hestia") return false;
      if (filter === "cloud" && site.via !== "cloud") return false;
      if (filter === "retry" && !site.retry) return false;
      const q = query.trim().toLowerCase();
      return q === "" || site.domain.toLowerCase().includes(q);
    })
  );

  function label(via: Site["via"]): string {
    return via === "hestia"
      ? "Via Hestia"
      : via === "cloud"
        ? "Via cloud relay"
        : via === "direct"
          ? "Direct"
          : "Needs retry";
  }

  function tone(via: Site["via"]): string {
    return via === "hestia" ? "share" : via === "cloud" ? "cloud" : via === "direct" ? "direct" : "warn";
  }

  function retry(site: Site) {
    toast.show(`Trying ${site.domain} again`);
  }
</script>

<div class="panel-page">
  <div class="panel-tools">
    <span class="summary">{protectionStats.unblocked} sites unblocked today</span>
    <div class="right">
      <label class="search">
        <Icon name="search" cls="sm" />
        <input bind:value={query} placeholder="Search sites" aria-label="Search sites" />
      </label>
      <div class="chips" role="group" aria-label="Filter sites">
        <button class="chip" class:active={filter === "all"} onclick={() => (filter = "all")}>All</button>
        <button class="chip" class:active={filter === "hestia"} onclick={() => (filter = "hestia")}>Via Hestia</button>
        <button class="chip" class:active={filter === "cloud"} onclick={() => (filter = "cloud")}>Via relay</button>
        <button class="chip" class:active={filter === "retry"} onclick={() => (filter = "retry")}>Needs retry</button>
      </div>
      <button class="btn small" onclick={() => toast.show("Thanks. We will check that site for you")}>
        <Icon name="plus" cls="sm" /> Report a site
      </button>
    </div>
  </div>

  <div class="card stats-pad">
    <div class="stats-card">
      <div class="stat-block"><span>Unblocked</span><strong>{protectionStats.unblocked}</strong></div>
      <div class="stat-block"><span>Via Hestia</span><strong>{protectionStats.via_hestia}</strong></div>
      <div class="stat-block"><span>Via cloud relay</span><strong>{protectionStats.via_cloud}</strong></div>
      <div class="stat-block"><span>Needs retry</span><strong>{protectionStats.retry}<em>site</em></strong></div>
    </div>
  </div>

  <div class="card sites-card">
    <div class="card-head"><h2>Sites</h2><span class="sub">today</span></div>
    {#each visible as site}
      <div class="site-row">
        <span class="name">{site.domain}</span>
        {#if site.retry}
          <button class="pill warn retry" title="Try this site again" onclick={() => retry(site)}>{label(site.via)}</button>
        {:else}
          <span class="pill {tone(site.via)}">{label(site.via)}</span>
        {/if}
        <span class="when">{site.retry ? "9 min" : "recently"}</span>
      </div>
    {:else}
      <p class="empty">No sites match that filter.</p>
    {/each}
  </div>

  <p class="note">
    <Icon name="shield" />
    <span><strong>Only blocked sites take the private path.</strong> Everything else stays on your normal connection. egress learns what your network blocks and shares that with your circle, never your browsing history.</span>
  </p>
</div>

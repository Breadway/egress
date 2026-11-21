<script lang="ts">
  import type { Site } from "$lib/api/types";
  import Icon from "$lib/components/Icon.svelte";
  import { app } from "$lib/state/app.svelte";
  import { toast } from "$lib/state/toast.svelte";

  type Filter = "all" | "friend" | "cloud" | "retry";

  let query = $state("");
  let filter = $state<Filter>("all");

  let stats = $derived(app.protection.stats);
  let visible = $derived(
    app.protection.sites.filter((site) => {
      if (filter === "friend" && site.via !== "friend") return false;
      if (filter === "cloud" && site.via !== "cloud") return false;
      if (filter === "retry" && !site.retry) return false;
      const q = query.trim().toLowerCase();
      return q === "" || site.domain.toLowerCase().includes(q);
    })
  );

  function tone(via: Site["via"]): string {
    return via === "friend" ? "share" : via === "cloud" ? "cloud" : via === "direct" ? "direct" : "warn";
  }

  async function retry(site: Site) {
    try {
      await app.retry(site.domain);
      toast.show(`Trying ${site.domain} again`);
    } catch (err) {
      toast.show(err instanceof Error ? err.message : "Could not queue that retry");
    }
  }

  async function reportSite() {
    const answer = window.prompt("Site address, for example example.com");
    if (!answer) return;
    try {
      await app.report(answer);
      toast.show(`Checking ${answer}`);
    } catch (err) {
      toast.show(err instanceof Error ? err.message : "Could not report that site");
    }
  }
</script>

<div class="panel-page">
  <div class="panel-tools">
    <span class="summary">{stats.unblocked} sites unblocked today</span>
    <div class="right">
      <label class="search">
        <Icon name="search" cls="sm" />
        <input bind:value={query} placeholder="Search sites" aria-label="Search sites" />
      </label>
      <div class="chips" role="group" aria-label="Filter sites">
        <button class="chip" class:active={filter === "all"} onclick={() => (filter = "all")}>All</button>
        <button class="chip" class:active={filter === "friend"} onclick={() => (filter = "friend")}>Via a friend</button>
        <button class="chip" class:active={filter === "cloud"} onclick={() => (filter = "cloud")}>Via relay</button>
        <button class="chip" class:active={filter === "retry"} onclick={() => (filter = "retry")}>Needs retry</button>
      </div>
      <button class="btn small" onclick={reportSite}>
        <Icon name="plus" cls="sm" /> Report a site
      </button>
    </div>
  </div>

  <div class="card stats-pad">
    <div class="stats-card">
      <div class="stat-block"><span>Unblocked</span><strong>{stats.unblocked}</strong></div>
      <div class="stat-block"><span>Via a friend</span><strong>{stats.via_friend}</strong></div>
      <div class="stat-block"><span>Via cloud relay</span><strong>{stats.via_cloud}</strong></div>
      <div class="stat-block"><span>Needs retry</span><strong>{stats.retry}<em>site</em></strong></div>
    </div>
  </div>

  <div class="card sites-card">
    <div class="card-head"><h2>Sites</h2><span class="sub">today</span></div>
    {#each visible as site}
      <div class="site-row">
        <span class="name">{site.domain}</span>
        {#if site.retry}
          <button class="pill warn retry" title="Try this site again" onclick={() => retry(site)}>{site.label}</button>
        {:else}
          <span class="pill {tone(site.via)}">{site.label}</span>
        {/if}
        <span class="when">{site.retry ? "retrying" : "recently"}</span>
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

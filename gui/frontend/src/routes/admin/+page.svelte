<script lang="ts">
  import type { AdminApplication } from "$lib/api/admin";
  import Icon from "$lib/components/Icon.svelte";
  import { admin, adminDate, appStateClass, appStateLabel } from "$lib/state/admin.svelte";

  let counts = $derived(admin.overview?.counts);
  let recent = $derived((admin.overview?.applications ?? []).slice(0, 8));

  const stats = $derived([
    { label: "Waiting", value: counts?.waiting ?? 0, tone: "" },
    { label: "Ready", value: counts?.ready ?? 0, tone: "accent" },
    { label: "Installed", value: counts?.installed ?? 0, tone: "green" },
    { label: "Attention", value: counts?.attention ?? 0, tone: counts?.attention ? "warn" : "" },
    { label: "Devices", value: counts?.devices ?? 0, tone: "" },
    { label: "Open invites", value: counts?.open_invites ?? 0, tone: "" }
  ]);

  function appSub(app: AdminApplication): string {
    const os = [app.os, app.arch].filter(Boolean).join("/");
    return [os, app.why].filter(Boolean).join(" · ");
  }
</script>

<div class="admin-stats">
  {#each stats as stat}
    <div class="admin-stat {stat.tone}">
      <span>{stat.label}</span>
      <strong>{stat.value}</strong>
    </div>
  {/each}
</div>

<article class="card">
  <div class="card-head">
    <h2>Recent applications</h2>
    <span class="sub">{admin.applications.length} total</span>
    <div class="right"><a class="card-link" href="/admin/applications">See all</a></div>
  </div>
  {#if recent.length === 0}
    <p class="empty">No applications yet.</p>
  {:else}
    <table class="admin-table">
      <thead><tr><th>Person</th><th>State</th><th>Created</th><th>Setup</th></tr></thead>
      <tbody>
        {#each recent as app}
          <tr>
            <td><span class="admin-name"><strong>{app.name}</strong><span>{appSub(app)}</span></span></td>
            <td><span class="pill {appStateClass(app.state)}">{appStateLabel(app.state)}</span></td>
            <td class="faint">{adminDate(app.created)}</td>
            <td class="faint">{app.setup_downloads ? `${app.setup_downloads} download${app.setup_downloads === 1 ? "" : "s"}` : "not yet"}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</article>

<div class="admin-shortcuts">
  <a class="card admin-shortcut" href="/admin/applications">
    <Icon name="check" />
    <span><strong>Applications</strong><span>Approve, reissue and remove requests.</span></span>
  </a>
  <a class="card admin-shortcut" href="/admin/devices">
    <Icon name="nodes" />
    <span><strong>Devices</strong><span>Invites, bound devices and open tokens.</span></span>
  </a>
</div>

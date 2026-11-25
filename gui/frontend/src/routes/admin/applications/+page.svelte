<script lang="ts">
  import type { AdminApplication } from "$lib/api/admin";
  import Icon from "$lib/components/Icon.svelte";
  import { admin, adminDate, appStateClass, appStateLabel } from "$lib/state/admin.svelte";
  import { toast } from "$lib/state/toast.svelte";

  type Filter = "all" | "waiting" | "ready" | "installed" | "failed";

  let query = $state("");
  let filter = $state<Filter>("all");
  let confirmDelete = $state<string | null>(null);

  let visible = $derived(
    admin.applications.filter((app) => {
      if (filter === "waiting" && app.state !== "waiting") return false;
      if (filter === "ready" && app.state !== "ready" && app.state !== "approved") return false;
      if (filter === "installed" && app.state !== "installed") return false;
      if (filter === "failed" && app.state !== "failed") return false;
      const q = query.trim().toLowerCase();
      return q === "" || app.name.toLowerCase().includes(q) || app.id.includes(q);
    })
  );

  function sub(app: AdminApplication): string {
    const os = [app.os, app.arch].filter(Boolean).join("/");
    return [os, app.why].filter(Boolean).join(" · ");
  }

  async function act(app: AdminApplication, action: "approve" | "reissue" | "delete") {
    try {
      if (action === "approve") {
        await admin.approve(app.id);
        toast.show(`Prepared the installer for ${app.name}`);
      } else if (action === "reissue") {
        await admin.reissue(app.id);
        toast.show(`Reissued the invite for ${app.name}`);
      } else {
        await admin.remove(app.id);
        confirmDelete = null;
        toast.show(`Deleted ${app.name}`);
      }
    } catch (err) {
      toast.show(err instanceof Error ? err.message : "The action failed");
    }
  }
</script>

<div class="panel-tools">
  <span class="summary">{admin.applications.length} requests</span>
  <div class="right">
    <label class="search">
      <Icon name="search" cls="sm" />
      <input bind:value={query} placeholder="Search applications" aria-label="Search applications" />
    </label>
    <div class="chips" role="group" aria-label="Filter applications">
      <button class="chip" class:active={filter === "all"} onclick={() => (filter = "all")}>All</button>
      <button class="chip" class:active={filter === "waiting"} onclick={() => (filter = "waiting")}>Waiting</button>
      <button class="chip" class:active={filter === "ready"} onclick={() => (filter = "ready")}>Ready</button>
      <button class="chip" class:active={filter === "installed"} onclick={() => (filter = "installed")}>Installed</button>
      <button class="chip" class:active={filter === "failed"} onclick={() => (filter = "failed")}>Failed</button>
    </div>
  </div>
</div>

<article class="card">
  {#if visible.length === 0}
    <p class="empty">No applications match this filter.</p>
  {:else}
    <table class="admin-table">
      <thead>
        <tr><th>Person</th><th>State</th><th>Device</th><th>Created</th><th></th></tr>
      </thead>
      <tbody>
        {#each visible as app}
          <tr>
            <td>
              <span class="admin-name">
                <strong>{app.name}</strong>
                <span>{sub(app)}</span>
              </span>
            </td>
            <td>
              <span class="pill {appStateClass(app.state)}">{appStateLabel(app.state)}</span>
              {#if app.provision_error}<span class="cell-error">{app.provision_error}</span>{/if}
            </td>
            <td class="faint">
              {#if app.device_id}
                <span class="mono">{app.device_id}</span>
                <span class="cell-sub">{app.device_status ?? "issued"}</span>
              {:else}
                not prepared
              {/if}
            </td>
            <td class="faint">{adminDate(app.created)}</td>
            <td>
              <div class="admin-actions">
                {#if !app.device_id}
                  <button class="btn small" disabled={admin.busy} onclick={() => act(app, "approve")}>
                    Approve &amp; prepare
                  </button>
                {:else}
                  <button class="btn small ghost" disabled={admin.busy} onclick={() => act(app, "reissue")}>
                    Reissue
                  </button>
                {/if}
                {#if confirmDelete === app.id}
                  <button class="btn small danger" disabled={admin.busy} onclick={() => act(app, "delete")}>Confirm</button>
                  <button class="btn small ghost" type="button" onclick={() => (confirmDelete = null)}>Cancel</button>
                {:else}
                  <button class="btn small ghost" disabled={admin.busy} onclick={() => (confirmDelete = app.id)}>Delete</button>
                {/if}
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</article>

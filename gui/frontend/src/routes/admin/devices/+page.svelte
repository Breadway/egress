<script lang="ts">
  import type { AdminInvite } from "$lib/api/admin";
  import Icon from "$lib/components/Icon.svelte";
  import { admin, adminDate } from "$lib/state/admin.svelte";
  import { toast } from "$lib/state/toast.svelte";

  let label = $state("");
  let creating = $state(false);
  let created = $state<AdminInvite | null>(null);
  let confirmRevoke = $state<string | null>(null);

  let bound = $derived(admin.devices.filter((d) => d.status === "bound").length);
  let open = $derived(admin.devices.filter((d) => d.status !== "bound").length);

  async function invite(event: SubmitEvent) {
    event.preventDefault();
    const name = label.trim();
    if (!name) return;
    creating = true;
    try {
      created = await admin.invite(name);
      label = "";
      toast.show(`Invite created for ${name}`);
    } catch (err) {
      toast.show(err instanceof Error ? err.message : "Could not create the invite");
    } finally {
      creating = false;
    }
  }

  async function copyToken() {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.token);
      toast.show("Invite token copied");
    } catch {
      toast.show("Select the token and copy it manually");
    }
  }

  async function revoke(id: string, name: string) {
    try {
      await admin.revoke(id);
      confirmRevoke = null;
      toast.show(`Revoked the invite for ${name}`);
    } catch (err) {
      toast.show(err instanceof Error ? err.message : "Could not revoke the invite");
    }
  }
</script>

<article class="card">
  <div class="card-head">
    <h2>Create an invite</h2>
    <span class="sub">{open} open · {bound} installed</span>
  </div>
  <form class="admin-form" onsubmit={invite}>
    <input
      class="input admin-label-input"
      bind:value={label}
      placeholder="Name, for example Ethan"
      aria-label="Invite label"
      maxlength="32"
    />
    <button class="btn primary" type="submit" disabled={creating || !label.trim()}>
      {creating ? "Creating" : "Create invite"}
    </button>
  </form>
  {#if created}
    <div class="token-box">
      <div class="token-head">
        <strong>Invite token for {created.label}</strong>
        <button class="btn small ghost" type="button" onclick={copyToken}>Copy</button>
        <button class="btn small ghost" type="button" onclick={() => (created = null)}>Dismiss</button>
      </div>
      <code>{created.token}</code>
      <p class="faint tiny">
        Shown once. The device uses it with the setup archive or
        <span class="mono">egress install --enroll-token</span>. Expires {adminDate(created.expires)}.
      </p>
    </div>
  {/if}
</article>

<article class="card admin-devices-card">
  {#if admin.devices.length === 0}
    <p class="empty">No devices or invites yet.</p>
  {:else}
    <table class="admin-table">
      <thead>
        <tr><th>Label</th><th>State</th><th>Address</th><th>Created</th><th></th></tr>
      </thead>
      <tbody>
        {#each admin.devices as device}
          <tr>
            <td>
              <span class="admin-name">
                <strong>{device.label || device.id}</strong>
                <span>{device.application_id ? `application ${device.application_id}` : device.id}</span>
              </span>
            </td>
            <td>
              <span class="pill {device.status === "bound" ? "direct" : ""}">{device.status}</span>
            </td>
            <td class="faint">
              {#if device.ip}
                <span class="mono">{device.ip}</span>
                <span class="cell-sub">{[device.platform, device.arch].filter(Boolean).join("/")}</span>
              {:else}
                waiting for the device
              {/if}
            </td>
            <td class="faint">
              {adminDate(device.bound_at || device.created)}
              {#if device.bound_at}<span class="cell-sub">bound</span>{/if}
            </td>
            <td>
              <div class="admin-actions">
                {#if device.status !== "bound"}
                  {#if confirmRevoke === device.id}
                    <button class="btn small danger" disabled={admin.busy} onclick={() => revoke(device.id, device.label || device.id)}>Confirm</button>
                    <button class="btn small ghost" type="button" onclick={() => (confirmRevoke = null)}>Cancel</button>
                  {:else}
                    <button class="btn small ghost" disabled={admin.busy} onclick={() => (confirmRevoke = device.id)}>Revoke</button>
                  {/if}
                {:else}
                  <span class="faint tiny">bound</span>
                {/if}
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</article>

<script lang="ts">
  import { page } from "$app/stores";
  import Icon from "$lib/components/Icon.svelte";
  import { admin } from "$lib/state/admin.svelte";
  import { toast } from "$lib/state/toast.svelte";

  let { children } = $props();

  admin.init();

  let token = $state("");
  let connecting = $state(false);

  const tabs = [
    { href: "/admin", label: "Overview" },
    { href: "/admin/applications", label: "Applications" },
    { href: "/admin/devices", label: "Devices" }
  ];

  function active(href: string): boolean {
    const path = $page.url.pathname;
    return href === "/admin" ? path === "/admin" || path === "/admin/" : path.startsWith(href);
  }

  async function connect(event: SubmitEvent) {
    event.preventDefault();
    const value = token.trim();
    if (!value) return;
    connecting = true;
    try {
      await admin.setToken(value);
      if (admin.error) toast.show(admin.error);
      else {
        toast.show("Admin connected");
        token = "";
      }
    } finally {
      connecting = false;
    }
  }

  function disconnect() {
    admin.disconnect();
    toast.show("Admin token removed");
  }
</script>

{#if !admin.token || (admin.error && !admin.overview)}
  <div class="panel-page narrow">
    <article class="card admin-gate">
      <div class="card-head">
        <Icon name="shield" />
        <h2>Admin access</h2>
      </div>
      <p class="muted">
        Paste the bypass admin token. It stays in this app and is sent through the
        local daemon over the tunnel; the daemon does not store it.
      </p>
      <form class="admin-form" onsubmit={connect}>
        <input
          class="input admin-token-input"
          bind:value={token}
          placeholder="Admin token"
          autocomplete="off"
          spellcheck="false"
        />
        <button class="btn primary" type="submit" disabled={connecting || !token.trim()}>
          {connecting ? "Connecting" : "Connect"}
        </button>
      </form>
      {#if admin.error}
        <p class="admin-error">{admin.error}</p>
      {/if}
      {#if admin.token}
        <button class="btn small ghost" type="button" onclick={disconnect}>Use a different token</button>
      {/if}
    </article>
  </div>
{:else}
  <div class="admin-shell">
    <div class="admin-tabs" role="tablist" aria-label="Admin sections">
      {#each tabs as tab}
        <a
          class="admin-tab"
          class:active={active(tab.href)}
          href={tab.href}
          aria-current={active(tab.href) ? "page" : undefined}
        >{tab.label}</a>
      {/each}
      <button class="btn small ghost admin-disconnect" type="button" onclick={disconnect}>Disconnect</button>
    </div>

    {#if admin.error}
      <p class="note admin-note">
        <Icon name="alert" cls="sm" />
        <span>{admin.error} <button class="linkish" type="button" onclick={() => admin.load()}>Retry</button></span>
      </p>
    {/if}

    {#if admin.loading && !admin.overview}
      <p class="empty">Loading the admin data...</p>
    {:else}
      {@render children()}
    {/if}
  </div>
{/if}

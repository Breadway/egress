<script lang="ts">
  import type { Person } from "$lib/api/types";
  import Icon from "$lib/components/Icon.svelte";
  import { people } from "$lib/data/mock";
  import { toast } from "$lib/state/toast.svelte";

  type Filter = "all" | "online" | "sharing";

  let query = $state("");
  let filter = $state<Filter>("all");

  const devices = $derived(people.filter((p) => p.kind === "device"));
  const friends = $derived(people.filter((p) => p.kind === "friend"));

  function matches(person: Person): boolean {
    if (filter === "online" && !person.online) return false;
    if (filter === "sharing" && !person.sharing) return false;
    const q = query.trim().toLowerCase();
    return q === "" || person.name.toLowerCase().includes(q);
  }

  function subtitle(person: Person): string {
    if (person.self) return "This laptop · you";
    if (person.kind === "device") return "Your device";
    if (person.sharing) return "Friend · sharing their connection";
    return "Friend";
  }

  function lastSeen(person: Person): string {
    if (!person.online) return "2 days ago";
    return "Online now";
  }

  function tone(person: Person): string {
    if (person.sharing) return "home";
    if (person.kind === "device") return person.self ? "" : "teal";
    if (person.name === "Caden") return "pink";
    return "grey";
  }

  function pillState(person: Person): string {
    if (person.self) return "accent";
    if (person.sharing) return "share";
    if (person.transport === "direct") return "direct";
    if (person.transport === "relay") return "relay";
    return "";
  }
</script>

<div class="panel-page">
  <div class="panel-tools">
    <span class="summary">Only people you invite can see you.</span>
    <div class="right">
      <label class="search">
        <Icon name="search" cls="sm" />
        <input bind:value={query} placeholder="Search friends" aria-label="Search friends" />
      </label>
      <div class="chips" role="group" aria-label="Filter friends">
        <button class="chip" class:active={filter === "all"} onclick={() => (filter = "all")}>All</button>
        <button class="chip" class:active={filter === "online"} onclick={() => (filter = "online")}>Online</button>
        <button class="chip" class:active={filter === "sharing"} onclick={() => (filter = "sharing")}>Sharing</button>
      </div>
    </div>
  </div>

  <div class="section-label">Your devices</div>
  <div class="card list-card">
    {#each devices.filter(matches) as person}
      <div class="friend-row">
        <div class="avatar sm {tone(person)}">
          {#if person.sharing}<Icon name="home" cls="sm" />{:else}{person.self ? "B" : person.name[0].toUpperCase()}{/if}
        </div>
        <div class="who"><strong>{person.name}</strong><span>{subtitle(person)}</span></div>
        {#if pillState(person)}
          <span class="pill {pillState(person)}">{person.self ? "This device" : person.transport === "relay" ? "Relayed" : "Direct"}</span>
        {:else}
          <span class="pill">Offline</span>
        {/if}
        <span class="meta">{lastSeen(person)}</span>
        <button class="more" aria-label={`More options for ${person.name}`} onclick={() => toast.show(`${person.name} · device options`)}>
          <Icon name="more" cls="sm" />
        </button>
      </div>
    {/each}
  </div>

  <div class="section-label">Friends</div>
  <div class="card list-card">
    {#each friends.filter(matches) as person}
      <div class="friend-row">
        <div class="avatar sm {tone(person)}">
          {#if person.sharing}<Icon name="home" cls="sm" />{:else}{person.name[0]}{/if}
        </div>
        <div class="who"><strong>{person.name}</strong><span>{subtitle(person)}</span></div>
        {#if pillState(person)}
          <span class="pill {pillState(person)}">{person.sharing ? "Sharing" : person.transport === "direct" ? "Direct" : "Relayed"}</span>
        {:else}
          <span class="pill">Offline</span>
        {/if}
        <span class="meta">{lastSeen(person)}</span>
        <button class="more" aria-label={`More options for ${person.name}`} onclick={() => toast.show(`${person.name} · friend options`)}>
          <Icon name="more" cls="sm" />
        </button>
      </div>
    {:else}
      <p class="empty">Nobody matches “{query}”.</p>
    {/each}
  </div>

  <p class="note">
    <Icon name="shield" />
    <span><strong>Your circle is private.</strong> Only people you invite can join, and you can remove someone at any time. Sharing your connection is always optional.</span>
  </p>
</div>

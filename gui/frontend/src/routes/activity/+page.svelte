<script lang="ts">
  import type { ActivityEvent, EventKind } from "$lib/api/types";
  import Icon from "$lib/components/Icon.svelte";
  import { events } from "$lib/data/mock";

  type Filter = "all" | EventKind;

  let filter = $state<Filter>("all");

  const visible = $derived(filter === "all" ? events : events.filter((event) => event.kind === filter));

  function icon(event: ActivityEvent): string {
    if (event.kind === "protection") return "shield";
    if (event.title.includes("helping")) return "check";
    if (event.title.includes("own connection")) return "nodes";
    if (event.title.includes("direct link")) return "bolt";
    if (event.title.includes("Started using")) return "globe";
    return "refresh";
  }

  function tone(event: ActivityEvent): string {
    if (event.kind === "protection" || event.title.includes("Started using")) return "accent";
    if (event.title.includes("helping") || event.title.includes("own connection")) return "teal";
    return event.title.includes("direct link") ? "green" : "";
  }
</script>

<div class="panel-page narrow">
  <div class="panel-tools">
    <span class="summary">Recent events on your connection</span>
    <div class="right">
      <div class="chips" role="group" aria-label="Filter activity">
        <button class="chip" class:active={filter === "all"} onclick={() => (filter = "all")}>All</button>
        <button class="chip" class:active={filter === "connection"} onclick={() => (filter = "connection")}>Connections</button>
        <button class="chip" class:active={filter === "friend"} onclick={() => (filter = "friend")}>Friends</button>
        <button class="chip" class:active={filter === "protection"} onclick={() => (filter = "protection")}>Protection</button>
      </div>
    </div>
  </div>

  <div class="card">
    {#each visible as event}
      <div class="event">
        <span class="time">{event.time}</span>
        <span class="mark {tone(event)}"><Icon name={icon(event)} cls="sm" /></span>
        <div class="text">{event.title}<small>{event.detail}</small></div>
      </div>
    {:else}
      <p class="empty">Nothing here yet today.</p>
    {/each}
  </div>
</div>

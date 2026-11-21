<script lang="ts">
  import type { Mode, Person, Site } from "$lib/api/types";
  import Icon from "$lib/components/Icon.svelte";
  import Sparkline from "$lib/components/Sparkline.svelte";
  import Toggle from "$lib/components/Toggle.svelte";
  import { events, people, sites } from "$lib/data/mock";
  import { connection } from "$lib/state/connection.svelte";
  import { toast } from "$lib/state/toast.svelte";

  const modes: { id: Mode; label: string }[] = [
    { id: "automatic", label: "Automatic" },
    { id: "direct", label: "Direct only" },
    { id: "friend", label: "Through a friend" }
  ];

  const friends = people.filter((p) => p.kind === "friend");
  const recentSites = sites.slice(0, 3);
  // The three events the design shows on Home: the friend hand-off, the direct
  // link and the most recent unblock.
  const recentEvents = [events[0], events[2], events[5]];
  let shareMine = $state(false);

  function setMode(mode: Mode) {
    connection.setMode(mode);
    if (mode === "direct") {
      toast.show("Direct only. Relay fallback is off");
    } else if (mode === "friend") {
      toast.show("Choose a friend from your circle to carry your connection");
    } else {
      toast.show("Automatic. Direct when possible, relay when needed");
    }
  }

  function viaLabel(via: Site["via"]): string {
    return via === "hestia" ? "Via Hestia" : via === "cloud" ? "Via cloud relay" : via === "direct" ? "Direct" : "Needs retry";
  }

  function viaClass(via: Site["via"]): string {
    return via === "hestia" ? "share" : via === "cloud" ? "cloud" : via === "direct" ? "direct" : "warn";
  }

  function personSub(person: Person): string {
    if (person.sharing) return "Sharing their connection";
    if (!person.online) return "Last seen 2 days ago";
    return person.kind === "device" ? "Your device" : "Friend · online";
  }

  function avatarTone(person: Person): string {
    if (person.sharing) return "home";
    if (person.name === "Caden") return "pink";
    return "grey";
  }

  function eventIcon(kind: string): string {
    return kind === "protection" ? "shield" : kind === "friend" ? "check" : "bolt";
  }

  function eventTone(kind: string): string {
    return kind === "protection" ? "accent" : kind === "friend" ? "teal" : "green";
  }
</script>

<div class="dashboard">
  <div class="col">
    <article class="card hero">
      <div class="hero-art"><Icon name="shield" /></div>
      <div class="hero-top">
        <span class="status-line" class:off={!connection.connected}>
          <i class="dot" class:pulse={connection.connected} class:off={!connection.connected}></i>
          {connection.statusLabel}
        </span>
        <span class="pill" class:accent={connection.connected}>{connection.routeLabel}</span>
        <span class="right"><a class="card-link" href="/activity">Details</a></span>
      </div>
      <div class="hero-main">
        <div class="big">{connection.unblocked}<span class="unit">sites</span></div>
        <div class="hero-label">unblocked today</div>
      </div>
      <div class="hero-metrics">
        <div class="metric">
          <span>Speed</span>
          <strong>{connection.connected ? connection.speed.toFixed(1) : "0.0"}<em>Mbps</em></strong>
        </div>
        <div class="metric"><span>Connected</span><strong>3h 12m</strong></div>
        <div class="metric"><span>Data</span><strong>{connection.dataGb}<em>GB</em></strong></div>
        <div class="metric"><span>Circle</span><strong>{connection.circleOnline}<em>online</em></strong></div>
      </div>
      <Sparkline />
    </article>

    <article class="card">
      <div class="card-head">
        <h2>Sites unblocked today</h2><span class="sub">{connection.unblocked} total</span>
        <div class="right"><a class="card-link" href="/protection">See all</a></div>
      </div>
      <div class="summary-bar" aria-hidden="true">
        <i class="a" style="width:62%"></i><i class="b" style="width:36%"></i><i class="c" style="width:2%"></i>
      </div>
      <div class="legend">
        <span><i style="background:var(--teal)"></i> Via Hestia · 36</span>
        <span><i style="background:var(--accent)"></i> Via cloud relay · 21</span>
        <span><i style="background:#4a4a4a"></i> Needs a retry · 1</span>
      </div>
      {#each recentSites as site}
        <div class="site-row">
          <span class="name">{site.domain}</span>
          <span class="pill {viaClass(site.via)}">{viaLabel(site.via)}</span>
          <span class="when">{site.via === "none" ? "9 min" : "now"}</span>
        </div>
      {/each}
    </article>

    <article class="card">
      <div class="card-head">
        <h2>Recent activity</h2>
        <div class="right"><a class="card-link" href="/activity">See all</a></div>
      </div>
      <div class="timeline">
        {#each recentEvents as event}
          <div class="event">
            <span class="time">{event.time}</span>
            <span class="mark {eventTone(event.kind)}"><Icon name={eventIcon(event.kind)} cls="sm" /></span>
            <div class="text">{event.title}<small>{event.detail}</small></div>
          </div>
        {/each}
      </div>
    </article>
  </div>

  <div class="col">
    <article class="card">
      <div class="card-head"><h2>Your connection</h2><span class="pill accent">{connection.modeLabel}</span></div>
      <div class="segmented">
        {#each modes as mode}
          <button class:active={connection.mode === mode.id} onclick={() => setMode(mode.id)}>{mode.label}</button>
        {/each}
      </div>
      <div class="path">
        <div class="path-step direct" class:active={connection.connected && connection.path === "direct"}>
          <div class="node"><Icon name="bolt" cls="sm" /></div>
          <div class="label">Direct</div><div class="path-note">preferred</div>
        </div>
        <div class="path-line"></div>
        <div class="path-step" class:active={connection.connected && connection.path === "relay"}>
          <div class="node"><Icon name="globe" cls="sm" /></div>
          <div class="label">Relay</div><div class="path-note">via {connection.exit}</div>
        </div>
        <div class="path-line"></div>
        <div class="path-step" class:active={connection.connected && connection.path === "cloud"}>
          <div class="node"><Icon name="server" cls="sm" /></div>
          <div class="label">Cloud backup</div><div class="path-note">if needed</div>
        </div>
      </div>
      <p class="path-hint">
        {#if !connection.connected}
          Connect to start protecting this device.
        {:else if connection.mode === "direct"}
          Direct only. Some sites may not be reachable through this network.
        {:else}
          A direct path was not available on this network. {connection.exit} is carrying your connection, so your traffic leaves through their home internet.
        {/if}
      </p>
    </article>

    <article class="card">
      <div class="card-head">
        <h2>Your circle</h2><span class="sub">{friends.length} people</span>
        <div class="right"><button class="btn small ghost" onclick={() => toast.show("Invite link copied")}><Icon name="plus" cls="sm" /> Invite</button></div>
      </div>
      <div class="people">
        {#each friends as person}
          <div class="person-row">
            <div class="avatar sm {avatarTone(person)}">
              {#if person.sharing}<Icon name="home" cls="sm" />{:else}{person.name[0]}{/if}
            </div>
            <div class="who"><strong>{person.name}</strong><span>{personSub(person)}</span></div>
            {#if person.sharing}
              <span class="pill share">Sharing</span>
            {:else if person.transport === "direct"}
              <span class="pill direct">Direct</span>
            {:else if person.transport === "relay"}
              <span class="pill relay">Relayed</span>
            {:else}
              <span class="pill">Offline</span>
            {/if}
          </div>
        {/each}
      </div>
      <div class="share-row">
        <div class="copy"><strong>Share my connection</strong><span>Help friends when they are blocked.</span></div>
        <div class="control"><Toggle bind:checked={shareMine} label="Share my connection" /></div>
      </div>
    </article>
  </div>
</div>

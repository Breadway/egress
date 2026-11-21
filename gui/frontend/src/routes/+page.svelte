<script lang="ts">
  import type { Mode, Person, Site } from "$lib/api/types";
  import Icon from "$lib/components/Icon.svelte";
  import Sparkline from "$lib/components/Sparkline.svelte";
  import Toggle from "$lib/components/Toggle.svelte";
  import { app, eventTime, relativeDay } from "$lib/state/app.svelte";
  import { toast } from "$lib/state/toast.svelte";

  const modes: { id: Mode; label: string }[] = [
    { id: "automatic", label: "Automatic" },
    { id: "direct", label: "Direct only" }
  ];

  let friends = $derived(app.friends);
  let recentSites = $derived(app.protection.sites.slice(0, 3));
  let recentEvents = $derived(app.activity.slice(0, 3));
  let stats = $derived(app.protection.stats);
  let total = $derived(Math.max(1, stats.via_friend + stats.via_cloud + stats.retry));
  let shareMine = $state(app.settings.share_connection);

  $effect(() => {
    shareMine = app.settings.share_connection;
  });

  let cloudExit = $derived(app.exit === "Cloud relay");
  let onDirect = $derived(app.connected && cloudExit && app.path === "direct");
  let onRelay = $derived(app.connected && !cloudExit);
  let onCloud = $derived(app.connected && cloudExit && app.path === "cloud");

  async function setMode(mode: Mode) {
    try {
      await app.setMode(mode);
      if (mode === "direct") {
        toast.show("Direct only. Relay fallback is off");
      } else {
        toast.show("Automatic. Direct when possible, relay when needed");
      }
    } catch (err) {
      toast.show(err instanceof Error ? err.message : "Could not change the mode");
    }
  }

  async function setSharing(enabled: boolean) {
    try {
      await app.patch({ share_connection: enabled });
      toast.show(enabled ? "Sharing is on for your circle" : "Sharing is off");
    } catch (err) {
      toast.show(err instanceof Error ? err.message : "Could not change sharing");
    }
  }

  async function copyInvite() {
    const url = "https://bypass.breadway.dev/apply";
    try {
      await navigator.clipboard.writeText(url);
      toast.show("Application link copied");
    } catch {
      // A webview without clipboard permission still gets the real link.
      toast.show(`Applications: ${url}`);
    }
  }

  function viaClass(via: Site["via"]): string {
    return via === "friend" ? "share" : via === "cloud" ? "cloud" : via === "direct" ? "direct" : "warn";
  }

  function personSub(person: Person): string {
    if (person.sharing) return "Sharing their connection";
    if (!person.online) return person.last_seen ? `Last seen ${relativeDay(person.last_seen)}` : "Offline";
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
        <span class="status-line" class:off={!app.connected}>
          <i class="dot" class:pulse={app.connected} class:off={!app.connected}></i>
          {app.statusLabel}
        </span>
        <span class="pill" class:accent={app.connected}>{app.routeLabel}</span>
        <span class="right"><a class="card-link" href="/activity">Details</a></span>
      </div>
      <div class="hero-main">
        <div class="big">{app.unblocked}<span class="unit">sites</span></div>
        <div class="hero-label">unblocked today</div>
      </div>
      <div class="hero-metrics">
        <div class="metric">
          <span>Speed</span>
          <strong>{app.connected ? app.speed.toFixed(1) : "0.0"}<em>Mbps</em></strong>
        </div>
        <div class="metric"><span>Connected</span><strong>{app.duration}</strong></div>
        <div class="metric"><span>Data</span><strong>{app.dataGb.toFixed(1)}<em>GB</em></strong></div>
        <div class="metric"><span>Circle</span><strong>{app.circleOnline}<em>online</em></strong></div>
      </div>
      <Sparkline />
    </article>

    <article class="card">
      <div class="card-head">
        <h2>Sites unblocked today</h2><span class="sub">{app.unblocked} total</span>
        <div class="right"><a class="card-link" href="/protection">See all</a></div>
      </div>
      <div class="summary-bar" aria-hidden="true">
        <i class="a" style={`width:${(stats.via_friend / total) * 100}%`}></i>
        <i class="b" style={`width:${(stats.via_cloud / total) * 100}%`}></i>
        <i class="c" style={`width:${(stats.retry / total) * 100}%`}></i>
      </div>
      <div class="legend">
        <span><i style="background:var(--teal)"></i> Via a friend · {stats.via_friend}</span>
        <span><i style="background:var(--accent)"></i> Via cloud relay · {stats.via_cloud}</span>
        <span><i style="background:#4a4a4a"></i> Needs a retry · {stats.retry}</span>
      </div>
      {#each recentSites as site}
        <div class="site-row">
          <span class="name">{site.domain}</span>
          <span class="pill {viaClass(site.via)}">{site.label}</span>
          <span class="when">{site.retry ? "retrying" : "now"}</span>
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
            <span class="time">{eventTime(event.time)}</span>
            <span class="mark {eventTone(event.kind)}"><Icon name={eventIcon(event.kind)} cls="sm" /></span>
            <div class="text">{event.title}<small>{event.detail}</small></div>
          </div>
        {/each}
      </div>
    </article>
  </div>

  <div class="col">
    <article class="card">
      <div class="card-head"><h2>Your connection</h2><span class="pill accent">{app.modeLabel}</span></div>
      <div class="segmented">
        {#each modes as mode}
          <button class:active={app.mode === mode.id} onclick={() => setMode(mode.id)}>{mode.label}</button>
        {/each}
      </div>
      <div class="path">
        <div class="path-step" class:active={onDirect}>
          <div class="node"><Icon name="bolt" cls="sm" /></div>
          <div class="label">Direct</div><div class="path-note">preferred</div>
        </div>
        <div class="path-line"></div>
        <div class="path-step" class:active={onRelay}>
          <div class="node"><Icon name="globe" cls="sm" /></div>
          <div class="label">Relay</div><div class="path-note">via {app.exit}</div>
        </div>
        <div class="path-line"></div>
        <div class="path-step" class:active={onCloud}>
          <div class="node"><Icon name="server" cls="sm" /></div>
          <div class="label">Cloud backup</div><div class="path-note">if needed</div>
        </div>
      </div>
      <p class="path-hint">
        {#if !app.connected}
          Connect to start protecting this device.
        {:else if app.mode === "direct"}
          Direct only. Some sites may not be reachable through this network.
        {:else if !cloudExit}
          {app.exit} is carrying your connection, so your traffic leaves through their internet.
        {:else}
          Blocked sites take the private path. Everything else stays on your normal connection.
        {/if}
      </p>
    </article>

    <article class="card">
      <div class="card-head">
        <h2>Your circle</h2><span class="sub">{friends.length} people</span>
        <div class="right"><button class="btn small ghost" onclick={copyInvite}><Icon name="plus" cls="sm" /> Invite</button></div>
      </div>
      <div class="people">
        {#each friends as person}
          <div class="person-row">
            <div class="avatar sm {avatarTone(person)}">
              {#if person.sharing}<Icon name="home" cls="sm" />{:else}{person.name ? person.name[0].toUpperCase() : "?"}{/if}
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
        <div class="control"><Toggle bind:checked={shareMine} label="Share my connection" onchange={() => setSharing(shareMine)} /></div>
      </div>
    </article>
  </div>
</div>

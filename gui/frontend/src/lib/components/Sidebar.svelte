<script lang="ts">
  import { page } from "$app/stores";
  import Icon from "$lib/components/Icon.svelte";
  import { app } from "$lib/state/app.svelte";

  const nav = [
    { href: "/", label: "Home", icon: "home" },
    { href: "/friends", label: "Friends", icon: "nodes" },
    { href: "/protection", label: "Protection", icon: "shield" },
    { href: "/activity", label: "Activity", icon: "pulse" },
    { href: "/settings", label: "Settings", icon: "sliders" }
  ];

  const badges = $derived<Record<string, string>>({
    "/friends": String(app.friends.filter((p) => p.online).length),
    "/protection": String(app.protection.stats.unblocked)
  });

  const self = $derived(app.people.find((p) => p.self));

  function active(href: string): boolean {
    const path = $page.url.pathname;
    return href === "/" ? path === "/" : path.startsWith(href);
  }
</script>

<aside class="sidebar">
  <div class="brand">
    <div class="brand-mark"><img src="/egress-icon.png" alt="" width="34" height="34" /></div>
    <div><div class="brand-name">egress</div><span class="brand-sub">private networking</span></div>
  </div>

  <div class="circle-chip">
    <span class="circle-dots"><i></i><i></i><i></i><i></i></span>
    <span>bread</span>
  </div>

  <nav class="nav" aria-label="Sections">
    <div class="nav-label">Your network</div>
    {#each nav.slice(0, 3) as item}
      <a
        class="nav-item"
        class:active={active(item.href)}
        href={item.href}
        aria-current={active(item.href) ? "page" : undefined}
      >
        <Icon name={item.icon} />
        {item.label}
        {#if badges[item.href]}<span class="badge">{badges[item.href]}</span>{/if}
      </a>
    {/each}
    <div class="nav-label">System</div>
    {#each nav.slice(3) as item}
      <a
        class="nav-item"
        class:active={active(item.href)}
        href={item.href}
        aria-current={active(item.href) ? "page" : undefined}
      >
        <Icon name={item.icon} />
        {item.label}
      </a>
    {/each}
  </nav>

  <div class="side-foot">
    <div class="protect" class:off={!app.connected}>
      <Icon name="shield" cls="sm" />
      {app.connected ? "Protected · smart routing" : "Protection is off"}
    </div>
    <div class="device-card">
      <div class="avatar">{self?.name?.[0]?.toUpperCase() ?? "B"}</div>
      <div class="device-meta"><strong>{self?.name ?? "This laptop"}</strong><span>This device</span></div>
      <i class="dot" class:off={!app.connected}></i>
    </div>
    <div class="side-version">egress {app.version}<br />{app.live ? "Service connected" : "Demo data"}</div>
  </div>
</aside>

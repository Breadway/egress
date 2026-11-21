<script lang="ts">
  import { page } from "$app/stores";
  import Icon from "$lib/components/Icon.svelte";
  import { connection } from "$lib/state/connection.svelte";

  const nav = [
    { href: "/", label: "Home", icon: "home" },
    { href: "/friends", label: "Friends", icon: "nodes", badge: "4" },
    { href: "/protection", label: "Protection", icon: "shield", badge: "58" },
    { href: "/activity", label: "Activity", icon: "pulse" },
    { href: "/settings", label: "Settings", icon: "sliders" }
  ];

  function active(href: string): boolean {
    const path = $page.url.pathname;
    return href === "/" ? path === "/" : path.startsWith(href);
  }
</script>

<aside class="sidebar">
  <div class="brand">
    <div class="brand-mark"><Icon name="bread" cls="lg" /></div>
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
        {#if item.badge}<span class="badge">{item.badge}</span>{/if}
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
    <div class="protect" class:off={!connection.connected}>
      <Icon name="shield" cls="sm" />
      {connection.connected ? "Protected · smart routing" : "Protection is off"}
    </div>
    <div class="device-card">
      <div class="avatar">B</div>
      <div class="device-meta"><strong>breadway</strong><span>This laptop</span></div>
      <i class="dot" class:off={!connection.connected}></i>
    </div>
    <div class="side-version">egress {connection.version}<br />Up to date</div>
  </div>
</aside>

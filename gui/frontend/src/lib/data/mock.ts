import type {
  ActivityEvent,
  Person,
  ProtectionStats,
  Settings,
  Site,
  Status
} from "../api/types";

// Fallback data for development and for the first launch before the daemon
// answers. Every screen reads the same store, so replacing this with live data
// is a store update, not a screen change.
export const status: Status = {
  version: "0.4.105",
  online: true,
  connected: true,
  connected_since: "2026-11-21T07:12:14Z",
  mode: "automatic",
  path: "relay",
  exit: "Hestia",
  speed_mbps: 20.0,
  data_gb: 1.2,
  unblocked_today: 58,
  circle_online: 5,
  network: "home"
};

export const people: Person[] = [
  {
    id: "breadway",
    name: "breadway",
    kind: "device",
    online: true,
    sharing: false,
    transport: "direct",
    last_seen: "2026-11-21T10:25:00Z",
    self: true
  },
  {
    id: "vm-test",
    name: "vm-test",
    kind: "device",
    online: true,
    sharing: false,
    transport: "relay",
    last_seen: "2026-11-21T10:25:00Z",
    self: false
  },
  {
    id: "hestia",
    name: "Hestia",
    kind: "friend",
    online: true,
    sharing: true,
    transport: "relay",
    last_seen: "2026-11-21T10:25:00Z",
    self: false
  },
  {
    id: "caden",
    name: "Caden",
    kind: "friend",
    online: true,
    sharing: false,
    transport: "direct",
    last_seen: "2026-11-21T10:25:00Z",
    self: false
  },
  {
    id: "ethan",
    name: "Ethan",
    kind: "friend",
    online: true,
    sharing: false,
    transport: "relay",
    last_seen: "2026-11-21T10:25:00Z",
    self: false
  },
  {
    id: "nathan",
    name: "Nathan",
    kind: "friend",
    online: false,
    sharing: false,
    transport: "offline",
    last_seen: "2026-11-19T18:20:00Z",
    self: false
  }
];

export const protectionStats: ProtectionStats = {
  unblocked: 58,
  via_friend: 36,
  via_cloud: 21,
  retry: 1
};

export const sites: Site[] = [
  { domain: "speed.cloudflare.com", via: "friend", label: "Hestia", at: "2026-11-21T10:25:00Z", retry: false },
  { domain: "1lmnv6z-m.ns1pcdn.net", via: "cloud", label: "Cloud relay", at: "2026-11-21T10:23:00Z", retry: false },
  { domain: "mega.nz", via: "friend", label: "Hestia", at: "2026-11-21T10:21:00Z", retry: false },
  { domain: "2.arch.pool.ntp.org", via: "none", label: "Needs retry", at: "2026-11-21T10:16:00Z", retry: true },
  { domain: "spd01-per.au.superloop.com", via: "cloud", label: "Cloud relay", at: "2026-11-21T10:14:00Z", retry: false },
  { domain: "rr1.sn-2ontq5-59.googlevideo.com", via: "friend", label: "Hestia", at: "2026-11-21T10:11:00Z", retry: false },
  { domain: "addons.liberationuage.com", via: "cloud", label: "Cloud relay", at: "2026-11-21T10:07:00Z", retry: false },
  { domain: "static.cloudflareinsights.com", via: "direct", label: "Direct", at: "2026-11-21T10:03:00Z", retry: false }
];

export const events: ActivityEvent[] = [
  {
    time: "2026-11-21T10:25:00Z",
    kind: "friend",
    title: "Hestia is now helping with your connection",
    detail: "relayed through their home internet · 20.0 Mbps"
  },
  {
    time: "2026-11-21T10:25:00Z",
    kind: "connection",
    title: "Your Windows PC got its own connection to Hestia",
    detail: "each device now gets its own connection"
  },
  {
    time: "2026-11-21T10:18:00Z",
    kind: "connection",
    title: "Found a direct link to Caden",
    detail: "faster path without a relay"
  },
  {
    time: "2026-11-21T10:12:00Z",
    kind: "connection",
    title: "Switched to the relay for your Windows PC",
    detail: "a direct path was not available"
  },
  {
    time: "2026-11-21T10:05:00Z",
    kind: "connection",
    title: "Your Windows PC refreshed its connection to Hestia",
    detail: "the new route is ready"
  },
  {
    time: "2026-11-21T09:58:00Z",
    kind: "protection",
    title: "Unblocked speed.cloudflare.com",
    detail: "learned by your circle · via Hestia"
  },
  {
    time: "2026-11-21T09:42:00Z",
    kind: "friend",
    title: "Started using Hestia's connection",
    detail: "Hestia chose to share with you"
  }
];

export const settings: Settings = {
  connect_automatically: true,
  relay_fallback: true,
  relay_region: "automatic",
  share_connection: false,
  share_scope: "friends",
  share_limit_gb: 50,
  hide_public_address: false,
  relay_only: false,
  share_reports: true,
  notify_friend: true,
  notify_site: false,
  notify_drop: true,
  text_size: "comfortable",
  mode: "automatic",
  exit_choice: ""
};

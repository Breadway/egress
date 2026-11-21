import type {
  ActivityEvent,
  Person,
  ProtectionStats,
  Settings,
  Site,
  Status
} from "../api/types";

// Shape of the local API. These values mirror the design mockup until the
// daemon endpoints land; every screen reads from this module so replacing it
// with the real client is a one-file change.
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
  via_hestia: 36,
  via_cloud: 21,
  retry: 1
};

export const sites: Site[] = [
  { domain: "speed.cloudflare.com", via: "hestia", at: "2026-11-21T10:25:00Z", retry: false },
  { domain: "1lmnv6z-m.ns1pcdn.net", via: "cloud", at: "2026-11-21T10:23:00Z", retry: false },
  { domain: "mega.nz", via: "hestia", at: "2026-11-21T10:21:00Z", retry: false },
  { domain: "2.arch.pool.ntp.org", via: "none", at: "2026-11-21T10:16:00Z", retry: true },
  { domain: "spd01-per.au.superloop.com", via: "cloud", at: "2026-11-21T10:14:00Z", retry: false },
  { domain: "rr1.sn-2ontq5-59.googlevideo.com", via: "hestia", at: "2026-11-21T10:11:00Z", retry: false },
  { domain: "addons.liberationuage.com", via: "cloud", at: "2026-11-21T10:07:00Z", retry: false },
  { domain: "static.cloudflareinsights.com", via: "direct", at: "2026-11-21T10:03:00Z", retry: false }
];

export const events: ActivityEvent[] = [
  {
    time: "10:25",
    kind: "friend",
    title: "Hestia is now helping with your connection",
    detail: "relayed through their home internet · 20.0 Mbps"
  },
  {
    time: "10:25",
    kind: "connection",
    title: "Your Windows PC got its own connection to Hestia",
    detail: "each device now gets its own connection"
  },
  {
    time: "10:18",
    kind: "connection",
    title: "Found a direct link to Caden",
    detail: "faster path without a relay"
  },
  {
    time: "10:12",
    kind: "connection",
    title: "Switched to the relay for your Windows PC",
    detail: "a direct path was not available"
  },
  {
    time: "10:05",
    kind: "connection",
    title: "Your Windows PC refreshed its connection to Hestia",
    detail: "the new route is ready"
  },
  {
    time: "09:58",
    kind: "protection",
    title: "Unblocked speed.cloudflare.com",
    detail: "learned by your circle · via Hestia"
  },
  {
    time: "09:42",
    kind: "friend",
    title: "Started using Hestia's connection",
    detail: "Hestia chose to share with you"
  }
];

export const settings: Settings = {
  connect_automatically: true,
  smart_routing: true,
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
  text_size: "comfortable"
};

export type Mode = "automatic" | "direct";
export type Path = "direct" | "relay" | "cloud" | "off";
export type Transport = "direct" | "relay" | "offline";
export type SiteVia = "friend" | "cloud" | "direct" | "none";
export type EventKind = "connection" | "friend" | "protection";

export interface Status {
  version: string;
  online: boolean;
  connected: boolean;
  connected_since: string;
  mode: Mode;
  path: Path;
  exit: string;
  speed_mbps: number;
  data_gb: number;
  unblocked_today: number;
  circle_online: number;
  network: string;
}

export interface Person {
  id: string;
  name: string;
  kind: "device" | "friend";
  online: boolean;
  sharing: boolean;
  transport: Transport;
  last_seen: string;
  self: boolean;
}

export interface Circle {
  circle: string;
  people: Person[];
}

export interface ProtectionStats {
  unblocked: number;
  via_friend: number;
  via_cloud: number;
  retry: number;
}

export interface Site {
  domain: string;
  via: SiteVia;
  label: string;
  at: string;
  retry: boolean;
}

export interface Protection {
  stats: ProtectionStats;
  sites: Site[];
}

export interface ActivityEvent {
  time: string;
  kind: EventKind;
  title: string;
  detail: string;
}

export interface ActivityResponse {
  events: ActivityEvent[];
}

export interface Settings {
  connect_automatically: boolean;
  relay_fallback: boolean;
  relay_region: "automatic" | "sydney" | "singapore" | "los_angeles";
  share_connection: boolean;
  share_scope: "friends" | "none";
  share_limit_gb: number;
  hide_public_address: boolean;
  relay_only: boolean;
  share_reports: boolean;
  notify_friend: boolean;
  notify_site: boolean;
  notify_drop: boolean;
  text_size: "comfortable" | "compact" | "large";
  mode: Mode;
}

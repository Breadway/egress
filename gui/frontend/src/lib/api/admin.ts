export interface AdminCounts {
  waiting: number;
  ready: number;
  installed: number;
  attention: number;
  devices: number;
  open_invites: number;
}

export interface AdminApplication {
  id: string;
  name: string;
  why?: string;
  os?: string;
  arch?: string;
  created: string;
  reviewed: boolean;
  state: string;
  device_id?: string;
  device_status?: string;
  provision_error?: string;
  setup_downloads: number;
  setup_downloaded?: string;
}

export interface AdminDevice {
  id: string;
  label?: string;
  status: string;
  ip?: string;
  platform?: string;
  arch?: string;
  created: string;
  bound_at?: string;
  expires?: string;
  pubkey?: string;
  relay_user?: string;
  application_id?: string;
}

export interface AdminOverview {
  counts: AdminCounts;
  applications: AdminApplication[];
}

export interface AdminInvite {
  ok: boolean;
  id: string;
  label: string;
  token: string;
  expires: string;
}

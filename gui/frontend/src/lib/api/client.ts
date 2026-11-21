import type {
  ActivityResponse,
  Circle,
  Protection,
  Settings,
  Status
} from "./types";

// Client for the local egress API. The daemon is the source of truth; this
// module is intentionally thin so the mock data can be replaced without
// touching any screen.
//
// The token is written by the daemon for the local user. Until the daemon
// endpoints land, callers use mock data and this client stays dormant.
const BASE = "http://127.0.0.1:7280/api/v1";

let token: string | null = null;

export function setToken(value: string | null) {
  token = value;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body?.error?.message ?? detail;
    } catch {
      // Keep the HTTP status text.
    }
    throw new Error(`${path}: ${res.status} ${detail}`);
  }
  return (await res.json()) as T;
}

export const api = {
  status: () => request<Status>("/status"),
  setConnected: (connected: boolean) =>
    request<Status>("/connection", {
      method: "POST",
      body: JSON.stringify({ connected })
    }),
  circle: () => request<Circle>("/circle"),
  protection: () => request<Protection>("/protection"),
  retrySite: (domain: string) =>
    request<{ ok: boolean }>("/protection/retry", {
      method: "POST",
      body: JSON.stringify({ domain })
    }),
  activity: (limit = 50) => request<ActivityResponse>(`/activity?limit=${limit}`),
  settings: () => request<Settings>("/settings"),
  patchSettings: (patch: Partial<Settings>) =>
    request<Settings>("/settings", {
      method: "PATCH",
      body: JSON.stringify(patch)
    })
};

// tryStatus is useful while the daemon endpoint is being built: the UI can
// fall back to the mock instead of showing an error on launch.
export async function tryStatus(): Promise<Status | null> {
  try {
    return await api.status();
  } catch {
    return null;
  }
}

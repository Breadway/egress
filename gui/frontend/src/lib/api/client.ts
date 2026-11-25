import type {
  ActivityEvent,
  ActivityResponse,
  Circle,
  Protection,
  Settings,
  Status
} from "./types";
import type { AdminApplication, AdminDevice, AdminInvite, AdminOverview } from "./admin";

// Client for the local egress API. The daemon is the source of truth.
const BASE = import.meta.env.VITE_EGRESS_API ?? "http://127.0.0.1:7280/api/v1";

let token: string | null = null;
let resolved = false;

function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

async function resolveToken(): Promise<string | null> {
  if (resolved) return token;
  resolved = true;
  const env = import.meta.env.VITE_EGRESS_TOKEN;
  if (env) {
    token = env;
    return token;
  }
  if (isTauri()) {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      token = await invoke<string>("api_token");
    } catch {
      token = null;
    }
  }
  return token;
}

export function resetToken() {
  token = null;
  resolved = false;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number
  ) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const current = await resolveToken();
  if (current) {
    headers.set("Authorization", `Bearer ${current}`);
  }
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (res.status === 401 && retry) {
    resetToken();
    return request<T>(path, init, false);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body?.error?.message ?? detail;
    } catch {
      // Keep the HTTP status text.
    }
    throw new ApiError(`${path}: ${detail}`, res.status);
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
  reportSite: (domain: string) =>
    request<{ ok: boolean }>("/protection/report", {
      method: "POST",
      body: JSON.stringify({ domain })
    }),
  activity: (limit = 50) => request<ActivityResponse>(`/activity?limit=${limit}`),
  clearActivity: () =>
    request<{ ok: boolean }>("/activity", {
      method: "DELETE"
    }),
  settings: () => request<Settings>("/settings"),
  patchSettings: (patch: Partial<Settings>) =>
    request<Settings>("/settings", {
      method: "PATCH",
      body: JSON.stringify(patch)
    })
};

function adminHeaders(token: string): HeadersInit {
  return {
    "X-Admin-Token": token,
    "Content-Type": "application/x-www-form-urlencoded"
  };
}

// Admin calls go through the local daemon so they use its tunnel on filtered
// networks. The admin token is passed per request and never stored by the
// daemon.
export const adminApi = {
  overview: (token: string) =>
    request<AdminOverview>("/admin/overview", { headers: { "X-Admin-Token": token } }),
  applications: (token: string) =>
    request<{ applications: AdminApplication[] }>("/admin/applications", {
      headers: { "X-Admin-Token": token }
    }),
  devices: (token: string) =>
    request<{ devices: AdminDevice[] }>("/admin/devices", {
      headers: { "X-Admin-Token": token }
    }),
  applicationAction: (token: string, id: string, action: "approve" | "reissue" | "delete") =>
    request<{ ok: boolean; state?: string }>("/admin/application", {
      method: "POST",
      headers: adminHeaders(token),
      body: new URLSearchParams({ id, action }).toString()
    }),
  invite: (token: string, label: string) =>
    request<AdminInvite>("/admin/device", {
      method: "POST",
      headers: adminHeaders(token),
      body: new URLSearchParams({ action: "invite", label }).toString()
    }),
  revoke: (token: string, id: string) =>
    request<{ ok: boolean }>("/admin/device", {
      method: "POST",
      headers: adminHeaders(token),
      body: new URLSearchParams({ action: "revoke", id }).toString()
    })
};

export interface StreamHandlers {
  onStatus: (status: Status) => void;
  onActivity: (event: ActivityEvent) => void;
  onError: () => void;
}

// openEvents streams live status and activity. Returns a stop function. The
// caller falls back to polling when onError fires.
export function openEvents(handlers: StreamHandlers): () => void {
  const controller = new AbortController();

  (async () => {
    const current = await resolveToken();
    if (!current) {
      handlers.onError();
      return;
    }
    try {
      const res = await fetch(`${BASE}/events`, {
        headers: {
          Authorization: `Bearer ${current}`,
          Accept: "text/event-stream"
        },
        signal: controller.signal
      });
      if (!res.ok || !res.body) {
        throw new Error(`events: ${res.status}`);
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let split = buffer.indexOf("\n\n");
        while (split >= 0) {
          const block = buffer.slice(0, split);
          buffer = buffer.slice(split + 2);
          parseBlock(block, handlers);
          split = buffer.indexOf("\n\n");
        }
      }
      if (!controller.signal.aborted) handlers.onError();
    } catch {
      if (!controller.signal.aborted) handlers.onError();
    }
  })();

  return () => controller.abort();
}

function parseBlock(block: string, handlers: StreamHandlers) {
  let event = "message";
  const data: string[] = [];
  for (const line of block.split("\n")) {
    if (line.startsWith("event:")) {
      event = line.slice(6).trim();
    } else if (line.startsWith("data:")) {
      data.push(line.slice(5).trimStart());
    }
  }
  if (data.length === 0) return;
  try {
    const value = JSON.parse(data.join("\n"));
    if (event === "status") {
      handlers.onStatus(value as Status);
    } else if (event === "activity") {
      handlers.onActivity(value as ActivityEvent);
    }
  } catch {
    // Ignore a partial or unknown frame and keep the stream alive.
  }
}

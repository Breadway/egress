import { adminApi } from "../api/client";
import type { AdminApplication, AdminDevice, AdminInvite, AdminOverview } from "../api/admin";

const TOKEN_KEY = "egress.adminToken";

class AdminState {
  token = $state("");
  overview = $state<AdminOverview | null>(null);
  applications = $state<AdminApplication[]>([]);
  devices = $state<AdminDevice[]>([]);
  loading = $state(false);
  busy = $state(false);
  error = $state<string | null>(null);

  private started = false;

  init() {
    if (this.started) return;
    this.started = true;
    if (typeof window === "undefined") return;
    const saved = window.localStorage.getItem(TOKEN_KEY);
    if (saved) {
      this.token = saved;
      void this.load();
    }
  }

  async setToken(token: string) {
    this.token = token.trim();
    if (typeof window !== "undefined") {
      window.localStorage.setItem(TOKEN_KEY, this.token);
    }
    await this.load();
  }

  disconnect() {
    this.token = "";
    this.overview = null;
    this.applications = [];
    this.devices = [];
    this.error = null;
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(TOKEN_KEY);
    }
  }

  async load() {
    if (!this.token) return;
    this.loading = true;
    this.error = null;
    try {
      const [overview, applications, devices] = await Promise.all([
        adminApi.overview(this.token),
        adminApi.applications(this.token),
        adminApi.devices(this.token)
      ]);
      this.overview = overview;
      this.applications = applications.applications ?? [];
      this.devices = devices.devices ?? [];
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Could not reach the admin service";
      this.overview = null;
      this.applications = [];
      this.devices = [];
    } finally {
      this.loading = false;
    }
  }

  private async act(fn: () => Promise<unknown>) {
    this.busy = true;
    this.error = null;
    try {
      await fn();
      await this.load();
    } catch (err) {
      this.error = err instanceof Error ? err.message : "The action failed";
      throw err;
    } finally {
      this.busy = false;
    }
  }

  approve(id: string) {
    return this.act(() => adminApi.applicationAction(this.token, id, "approve"));
  }

  reissue(id: string) {
    return this.act(() => adminApi.applicationAction(this.token, id, "reissue"));
  }

  remove(id: string) {
    return this.act(() => adminApi.applicationAction(this.token, id, "delete"));
  }

  async invite(label: string): Promise<AdminInvite> {
    this.busy = true;
    this.error = null;
    try {
      const invite = await adminApi.invite(this.token, label);
      await this.load();
      return invite;
    } catch (err) {
      this.error = err instanceof Error ? err.message : "Could not create the invite";
      throw err;
    } finally {
      this.busy = false;
    }
  }

  revoke(id: string) {
    return this.act(() => adminApi.revoke(this.token, id));
  }
}

export const admin = new AdminState();

export function adminDate(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleDateString([], { day: "numeric", month: "short" }) +
    " " +
    date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

export function appStateClass(state: string): string {
  switch (state) {
    case "installed":
      return "direct";
    case "ready":
    case "approved":
      return "accent";
    case "failed":
      return "warn";
    default:
      return "";
  }
}

export function appStateLabel(state: string): string {
  switch (state) {
    case "installed":
      return "Installed";
    case "ready":
      return "Ready";
    case "approved":
      return "Approved";
    case "failed":
      return "Failed";
    case "waiting":
      return "Waiting";
    default:
      return state || "Unknown";
  }
}

import { api, openEvents } from "../api/client";
import { notify } from "../notify";
import type {
  ActivityEvent,
  Circle,
  Mode,
  Person,
  Protection,
  Settings,
  Status
} from "../api/types";
import { events, people, protectionStats, settings, sites, status } from "../data/mock";

// AppState is the single live model behind every screen. It starts on the
// approved mock data so the UI renders immediately, then swaps to the daemon
// API as soon as the local token and endpoint answer.
class AppState {
  status = $state<Status>({ ...status });
  people = $state<Person[]>([...people]);
  protection = $state<Protection>({ stats: { ...protectionStats }, sites: [...sites] });
  activity = $state<ActivityEvent[]>([...events]);
  settings = $state<Settings>({ ...settings });
  live = $state(false);
  ready = $state(false);
  error = $state<string | null>(null);

  private started = false;
  private poll: ReturnType<typeof setInterval> | null = null;
  private stopStream: (() => void) | null = null;
  private lastRefresh = 0;

  get connected() {
    return this.status.connected;
  }
  get path() {
    return this.status.connected ? this.status.path : "off";
  }
  get unblocked() {
    return this.status.unblocked_today;
  }
  get dataGb() {
    return this.status.data_gb;
  }
  get speed() {
    return this.status.speed_mbps;
  }
  get circleOnline() {
    return this.status.circle_online;
  }
  get version() {
    return this.status.version;
  }
  get exit() {
    return this.status.exit;
  }
  get mode() {
    return this.settings.mode;
  }
  get friends() {
    return this.people.filter((p) => p.kind === "friend");
  }
  get devices() {
    return this.people.filter((p) => p.kind === "device");
  }
  get statusLabel() {
    return this.connected ? "Protected" : "Disconnected";
  }
  get routeLabel() {
    if (!this.connected) return "Not connected";
    if (this.mode === "direct") return "Direct";
    if (this.exit !== "Cloud relay") return `Relayed via ${this.exit}`;
    return this.status.path === "direct" ? "Direct" : "Relayed via the cloud";
  }
  get modeLabel() {
    if (this.mode === "direct") return "Direct only";
    return "Automatic";
  }
  get duration() {
    const since = Date.parse(this.status.connected_since);
    if (!this.connected || Number.isNaN(since)) return "0m";
    const mins = Math.max(0, Math.round((Date.now() - since) / 60000));
    if (mins < 60) return `${mins}m`;
    return `${Math.floor(mins / 60)}h ${mins % 60}m`;
  }

  async start() {
    if (this.started) return;
    this.started = true;
    await this.load();
    if (this.live) {
      this.stream();
    } else {
      this.pollNow();
    }
  }

  private async load() {
    try {
      const [nextStatus, circle, protection, activity, settings] = await Promise.all([
        api.status(),
        api.circle(),
        api.protection(),
        api.activity(100),
        api.settings()
      ]);
      this.status = nextStatus;
      this.people = circle.people?.length ? circle.people : this.people;
      this.protection = protection;
      this.activity = activity.events;
      this.settings = settings;
      this.live = true;
      this.error = null;
      return true;
    } catch (err) {
      this.live = false;
      this.error = err instanceof Error ? err.message : String(err);
      return false;
    } finally {
      this.ready = true;
    }
  }

  private stream() {
    this.stopStream?.();
    this.stopStream = openEvents({
      onStatus: (next) => {
        const changedExit = next.exit !== this.status.exit;
        const changedPath = next.path !== this.status.path;
        this.status = next;
        this.live = true;
        if (changedExit || changedPath) {
          this.refreshProtection();
          api
            .circle()
            .then((circle) => (this.people = circle.people?.length ? circle.people : this.people))
            .catch(() => {});
        }
      },
      onActivity: (event) => {
        this.addEvent(event);
        this.maybeNotify(event);
        this.refreshSoon();
      },
      onError: () => {
        this.stopStream?.();
        this.stopStream = null;
        this.pollNow();
      }
    });
  }

  private pollNow() {
    if (this.poll) return;
    this.poll = setInterval(async () => {
      const ok = await this.load();
      if (ok) {
        if (this.poll) clearInterval(this.poll);
        this.poll = null;
        this.stream();
      }
    }, 5000);
  }

  private addEvent(event: ActivityEvent) {
    const key = `${event.time}|${event.title}`;
    if (this.activity.some((e) => `${e.time}|${e.title}` === key)) return;
    this.activity = [event, ...this.activity].slice(0, 200);
  }

  // An activity row means circle or protection state changed. Refresh both,
  // at most once every two seconds, so a burst of events does not flood the
  // daemon with requests.
  private refreshSoon() {
    const now = Date.now();
    if (now - this.lastRefresh < 2000) return;
    this.lastRefresh = now;
    this.refreshProtection();
    api
      .circle()
      .then((circle) => (this.people = circle.people?.length ? circle.people : this.people))
      .catch(() => {});
  }

  private maybeNotify(event: ActivityEvent) {
    if (!this.live) return;
    if (
      event.kind === "friend" &&
      this.settings.notify_friend &&
      !event.title.includes("offline")
    ) {
      void notify("Your circle", event.title);
      return;
    }
    if (event.kind === "protection" && this.settings.notify_site && event.title.startsWith("Unblocked")) {
      void notify("Site unblocked", event.title);
      return;
    }
    if (event.kind === "connection" && this.settings.notify_drop && event.title.includes("Protection is paused")) {
      void notify("Protection paused", "Your normal connection is back.");
    }
  }

  async refreshAll() {
    const ok = await this.load();
    if (!ok) throw new Error(this.error ?? "Could not reach the egress service");
  }

  async toggle(): Promise<boolean> {
    const next = !this.connected;
    this.status = await api.setConnected(next);
    return next;
  }

  async setMode(mode: Mode) {
    const saved = await api.patchSettings({ mode });
    this.settings = saved;
    this.status.mode = mode;
  }

  async patch(patch: Partial<Settings>) {
    const saved = await api.patchSettings(patch);
    this.settings = saved;
    if (patch.mode) this.status.mode = patch.mode;
    return saved;
  }

  async retry(domain: string) {
    await api.retrySite(domain);
    setTimeout(() => {
      api
        .protection()
        .then((p) => (this.protection = p))
        .catch(() => {});
    }, 1500);
  }

  async report(domain: string) {
    await api.reportSite(domain);
    setTimeout(() => {
      api
        .protection()
        .then((p) => (this.protection = p))
        .catch(() => {});
    }, 4000);
  }

  async clearActivity() {
    await api.clearActivity();
    this.activity = [];
  }

  async refreshProtection() {
    try {
      this.protection = await api.protection();
      this.status = await api.status();
    } catch {
      // Keep the last good picture; the stream or poll will catch up.
    }
  }
}

export const app = new AppState();

// eventTime renders an RFC3339 timestamp as the short local clock time the
// Activity screen uses.
export function eventTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

export function relativeDay(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  const days = Math.floor((Date.now() - date.getTime()) / 86400000);
  if (days <= 0) return "Online now";
  if (days === 1) return "Yesterday";
  return `${days} days ago`;
}

export type { Circle };

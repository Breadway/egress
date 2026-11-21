import type { Mode } from "../api/types";
import { status } from "../data/mock";

class ConnectionState {
  connected = $state(status.connected);
  mode = $state<Mode>(status.mode);
  speed = $state(status.speed_mbps);
  dataGb = $state(status.data_gb);
  unblocked = $state(status.unblocked_today);
  circleOnline = $state(status.circle_online);
  readonly version = status.version;
  readonly exit = status.exit;

  get path(): "direct" | "relay" | "cloud" | "off" {
    if (!this.connected) return "off";
    return status.path;
  }

  get routeLabel(): string {
    if (!this.connected) return "Not connected";
    if (this.mode === "direct") return "Direct";
    if (this.mode === "friend") return `Through ${this.exit}`;
    return `Relayed via ${this.exit}`;
  }

  get modeLabel(): string {
    if (this.mode === "direct") return "Direct only";
    if (this.mode === "friend") return "Through a friend";
    return "Automatic";
  }

  get statusLabel(): string {
    return this.connected ? "Protected" : "Disconnected";
  }

  toggle() {
    this.connected = !this.connected;
  }

  setMode(mode: Mode) {
    this.mode = mode;
  }
}

export const connection = new ConnectionState();

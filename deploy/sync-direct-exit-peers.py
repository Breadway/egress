#!/usr/bin/env python3
"""Push the fleet's bound devices to a direct exit as WireGuard peers.

The exit is not a peer of Aegis, so nothing on the router side can configure it.
Aegis already knows every bound device's public key and tunnel address, so it
applies that list over SSH. Idempotent: peers are added or updated, and peers
whose address is in the tunnel subnet but which are no longer bound are removed.
"""
import json
import os
import shutil
import subprocess
import sys

DEVICES = os.environ.get("DIRECT_EXIT_DEVICES", "/var/lib/bypass/devices.json")
HOST = os.environ.get("DIRECT_EXIT_HOST", "140.238.198.192")
KEY = os.environ.get("DIRECT_EXIT_KEY", "/root/.ssh/id_ed25519")
USER = os.environ.get("DIRECT_EXIT_USER", "ubuntu")
SUBNET = "10.88.0."


def desired() -> dict[str, str]:
    try:
        data = json.load(open(DEVICES))
    except Exception as exc:  # noqa: BLE001
        print(f"devices: {exc}", file=sys.stderr)
        return {}
    out = {}
    for dev in data.get("devices", []):
        ip, key = dev.get("ip", ""), dev.get("pubkey", "")
        if dev.get("status") == "bound" and ip.startswith(SUBNET) and key:
            out[key] = ip + "/32"
    return out


def ssh(script: str) -> subprocess.CompletedProcess:
    cmd = [
        "ssh", "-i", KEY,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        f"{USER}@{HOST}", "sudo bash -s",
    ]
    return subprocess.run(cmd, input=script, text=True, capture_output=True, check=True)


def main() -> int:
    want = desired()
    try:
        cur = ssh("wg show wg0 allowed-ips")
    except subprocess.CalledProcessError as exc:
        print(f"query failed: {exc.stderr.strip()}", file=sys.stderr)
        return 1

    have = {}
    for line in cur.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        peer, cidrs = parts[0], parts[1:]
        if any(c.startswith(SUBNET) for c in cidrs):
            have[peer] = cidrs

    lines = [f"wg set wg0 peer '{key}' allowed-ips {cidr}" for key, cidr in want.items()]
    stale = [key for key in have if key not in want]
    lines += [f"wg set wg0 peer '{key}' remove" for key in stale]
    if not lines:
        print("nothing to change")
        return 0
    try:
        ssh("\n".join(lines) + "\n")
    except subprocess.CalledProcessError as exc:
        print(f"apply failed: {exc.stderr.strip()}", file=sys.stderr)
        return 1
    print(f"synced {len(want)} bound devices, removed {len(stale)}")

    # Publish the star endpoints so clients can attempt direct links. Aegis
    # learns every peer's NAT mapping from the WireGuard handshakes, which is
    # the address a direct attempt has to dial.
    try:
        seen = subprocess.run(["wg", "show", "wg0", "endpoints"],
                              capture_output=True, text=True, check=True)
        mapping = {}
        for line in seen.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] not in ("(none)", ""):
                mapping[parts[0]] = parts[1]
        tmp = "/var/lib/bypass/endpoints.json.tmp"
        with open(tmp, "w") as fh:
            json.dump(mapping, fh)
        os.replace(tmp, "/var/lib/bypass/endpoints.json")
        os.chmod("/var/lib/bypass/endpoints.json", 0o640)
        shutil.chown("/var/lib/bypass/endpoints.json", "bypass", "bypass")
    except Exception as exc:  # noqa: BLE001
        print(f"endpoints: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

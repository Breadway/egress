#!/usr/bin/env python3
"""Provision approved bypass applications.

Runs on hermes as the breadway user. It polls the tailnet-only admin API on
Aegis, claims one approved application, runs new-device.sh and
publish-device.sh, then repeats. Aegis never initiates into the home network.

The generated download password is intentionally not logged: the applicant
sets their own from the status link.
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = os.path.dirname(os.path.abspath(__file__))
API = os.environ.get("BYPASS_API", "https://aegis-1.tail4806cb.ts.net:7221")
POLL_SECONDS = int(os.environ.get("BYPASS_POLL_SECONDS", "30"))
ONLY = os.environ.get("BYPASS_ONLY", "")
DEBUG_BUILD = os.environ.get("BYPASS_DEBUG_BUILD", "") not in ("", "0", "false", "no")
TOKEN = None


def log(message):
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), message, flush=True)


def token():
    global TOKEN
    if TOKEN:
        return TOKEN
    while True:
        try:
            result = subprocess.run(
                [
                    "ssh",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=10",
                    "aegis",
                    "sudo cat /etc/bypass/admin-token",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            TOKEN = result.stdout.strip()
            if TOKEN:
                return TOKEN
        except (subprocess.SubprocessError, OSError) as exc:
            log(f"token fetch failed: {exc}")
        time.sleep(POLL_SECONDS)


def api(path, data=None):
    global TOKEN
    body = urllib.parse.urlencode(data).encode() if data else None
    request = urllib.request.Request(
        API + path,
        data=body,
        headers={"Authorization": "Bearer " + token()},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            TOKEN = None
        if exc.code in (401, 404, 409):
            return None
        raise
    except urllib.error.URLError as exc:
        log(f"api {path}: {exc}")
        return None


def label_for(app):
    slug = re.sub(r"[^a-z0-9]+", "-", app["name"].lower()).strip("-")[:24].strip("-")
    return f"{slug or 'user'}-{app['id'][:6]}"


def registered(label):
    path = os.path.expanduser("~/.keys/egress-peers.tsv")
    try:
        with open(path) as handle:
            return any(line.split("\t", 1)[0] == label for line in handle)
    except OSError:
        return False


def run(command):
    result = subprocess.run(
        command,
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=900,
    )
    if result.returncode != 0:
        # Keep output out of the journal and the server: publish-device.sh
        # prints the generated download password on success.
        log(f"{command[0]} failed with exit {result.returncode}")
        return False
    return True


def main():
    log("provisioner started")
    while True:
        pending = api("/admin/api/pending")
        if ONLY:
            pending = [item for item in (pending or []) if item["id"] == ONLY]
        if not pending:
            time.sleep(POLL_SECONDS)
            continue
        app = pending[0]
        claimed = api("/admin/api/claim", {"id": app["id"]})
        if not claimed:
            time.sleep(5)
            continue
        label = label_for(claimed)
        target_os = claimed.get("os") or "windows"
        target_arch = claimed.get("arch") or (
            "arm64" if target_os == "darwin" else "amd64"
        )
        log(f"provisioning {claimed['id']} as {label} ({target_os}/{target_arch})")
        new_device_args = [
            "./new-device.sh",
            "--name",
            label,
            "--os",
            target_os,
            "--arch",
            target_arch,
        ]
        if DEBUG_BUILD:
            new_device_args.append("--debug-build")
        ok = True
        if not registered(label):
            ok = run(new_device_args)
        if ok:
            ok = run(
                [
                    "./publish-device.sh",
                    "--name",
                    label,
                    "--application",
                    claimed["id"],
                    "--os",
                    target_os,
                    "--arch",
                    target_arch,
                ]
            )
        if ok:
            log(f"provisioned {claimed['id']} as {label}")
        else:
            api(
                "/admin/api/release",
                {
                    "id": claimed["id"],
                    "error": "provisioning failed; check journalctl -u bypass-provisioner on hermes",
                },
            )
        time.sleep(5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)

# egress

A single binary that gives a Linux or Windows machine:

- DNS over HTTPS through `https://dns.breadway.dev/dns-query`, served locally on
  `127.0.0.1:7103`
- split routing: only destinations proven blocked take the tunnel through
  Aegis (`152.69.174.7`); everything else stays on the local link, so a client
  cannot spend the relay's bandwidth on ordinary browsing
- an automatic WebSocket fallback on `wss://dns.breadway.dev/wg-tunnel` when UDP
  is blocked or throttled

It is the portable version of the hermes bypass. The DoH client, the local DNS
server, the fallback supervisor, key validation and public-key derivation are
all in the binary. Delivery builds also embed the pinned `wstunnel` 11.1.0
client, and Windows builds additionally embed the signed WireGuard installer,
so the target machine needs no GitHub, winget, or package manager access
before the tunnel is up. There are no Go module dependencies.

The binary is a credential. It can be built with a private key compiled in, so
anyone holding the file can use it. Do not publish it or commit it.

## Quick start

You need an enrolled WireGuard private key. Aegis must already list the matching
public key as a peer with a unique `/32` (the default tunnel address is
`10.88.0.4`; hermes is `10.88.0.2`). The helper below does the enrollment and
build together; the manual path follows it.

### Provision a new device in one command

If this machine can SSH to Aegis and has passwordless sudo there, the helper
does the whole provisioning step:

```sh
cd ~/Projects/Apps/egress
./new-device.sh --name sam
```

It checks the live `wg0` peers and `wg0.conf`, picks the lowest free address in
the tunnel subnet, generates a key, saves the private half to
`~/.keys/egress-sam-<ip>.key` mode 0600, appends the peer to
`/etc/wireguard/wg0.conf`, applies it with `wg set`, and builds
`dist/egress-sam-<ip>.exe` with the fallback and WireGuard installer
embedded. The private key is never printed. Successful
devices are recorded in the private local registry
`~/.keys/egress-peers.tsv`, keyed by the label.

Useful options:

```sh
./new-device.sh --dry-run --name sam   # show the address it would pick, change nothing
./new-device.sh --ip 10.88.0.7         # force an address
./new-device.sh --name sam --os linux  # build a Linux binary instead
./new-device.sh --name sam --os both   # build both Windows and Linux binaries
AEGIS_HOST=ubuntu@host ./new-device.sh # different SSH target
```

A Linux binary is the same single file: the `wstunnel` fallback client is
embedded, so the target needs no GitHub access. It still needs
`wireguard-tools` from its package manager plus root and systemd.

The script needs `ssh`, `wg` and `go` locally, and prints the binary path, its
SHA-256, the Aegis backup path, and the exact steps for the Windows laptop.

List and revoke registered devices by label:

```sh
./remove-device.sh --list
./remove-device.sh --name sam
```

The removal command backs up Aegis's `wg0.conf`, removes precisely the peer
block that `new-device.sh` added, removes the live peer, deletes the registry
entry, and deletes the local key and generated binary. Use `--keep-files` to
revoke network access while retaining the local files for a rollback.

### Let the owner download the installer themselves

Instead of sending the 20 MB binary, publish it to
`https://bypass.breadway.dev/download` behind a username and password:

```sh
./publish-device.sh --name sam
./publish-device.sh --name sam --os linux
./publish-device.sh --name sam --user sam-laptop --password '...'
```

With no `--password`, one is generated and printed once. The password is
stored on Aegis as bcrypt plus a recoverable copy (0600, service account
only) so the applicant's status page can show it and offer a one-click
download link. Anyone holding the status link already has full access to
that account. The admin Logins table shows each password; Reset issues a
new one.

Strangers go through the site instead: `/apply` takes a name, why they
need access, and Windows or Linux (no contact info), and hands back a secret
status link to bookmark. Review applications and link download logins in the admin UI at
`https://aegis-1.tail4806cb.ts.net:7221/admin` (session login; credentials in
`/etc/bypass/env` on Aegis). It is served by Tailscale Serve on the tailnet
only; `bypass.breadway.dev/admin*` returns 404.

Approving an application queues it. A pull-based provisioner on hermes picks
it up, runs `new-device.sh --os <selected>`, uploads with
`publish-device.sh --os <selected>`, and links the login. It usually completes
in under a minute. The applicant's status link then shows the issued login
and a one-click download button. Aegis never initiates into the home network.

The provisioner is `provision-pending.py`, installed as a system service:

```sh
sudo install -m 0644 deploy/bypass-provisioner.service /etc/systemd/system/
sudo systemctl enable --now bypass-provisioner
journalctl -u bypass-provisioner -f
```

If provisioning fails, the application shows an error in the admin UI and
stops retrying. Fix the cause, then press Retry. The manual path still works:
`new-device.sh --name <label>`, then
`publish-device.sh --name <label> --application <id>`.

Server source is in `bypass-server/` (stdlib plus x/crypto), running on Aegis
as the `bypass` user behind Caddy.

### Build a self-contained binary

On Linux:

```sh
./build.sh --generate --ip 10.88.0.4 --os windows   # dist/egress-windows-amd64.exe
./build.sh --key-file ~/.keys/device4.key --ip 10.88.0.4 --os linux
```

`--quiet` suppresses the private key, the next-steps text and the warning; the
provisioning script uses it.

On Windows (PowerShell):

```powershell
.\build.ps1 -Generate -IP 10.88.0.4
.\build.ps1 -KeyFile .\device4.key -IP 10.88.0.4
```

`--generate` / `-Generate` makes a new key and prints both the private and the
public key. `build.sh` prints the public key through `wg pubkey` when `wg` is
available; otherwise run the built binary with `egress pubkey` to get it.

Before first use on the target machine, add the printed public key on Aegis:

```sh
wg set wg0 peer '<public key>' allowed-ips 10.88.0.4/32
# and the same [Peer] block in /etc/wireguard/wg0.conf
```

Then copy only the binary to the target and run it as root or Administrator.

### Install

Linux:

```sh
sudo ./egress-linux-amd64 install
```

Windows, from an elevated PowerShell:

```powershell
.\egress-windows-amd64.exe install --debug
```

Windows delivery builds need no separate installer. If WireGuard for Windows is
missing, `install` extracts the embedded signed MSI, verifies its checksum and
Authenticode signer, and installs it silently. It also extracts the embedded
`wstunnel.exe`, so a blocked GitHub download cannot disable the fallback.

If the binary has no embedded key, `install` prompts for one, or accepts
`--key <base64>` / `--key-file <path>`. Key validation happens before anything
on the machine is changed.

## First Windows test

The Windows service runs detached, so start the first run with `--debug` to get
a log file, and keep that log when reporting a failure.

1. Nothing to install separately. The binary carries the signed WireGuard MSI
   and `wstunnel.exe`.
2. Add the device public key to Aegis with the same `/32` as `--ip`.
3. Open an elevated PowerShell in the folder containing the binary and run it
   from anywhere: `install` copies itself to
   `C:\ProgramData\egress\egress.exe` and points the scheduled task
   there, so Downloads, USB sticks and network shares are fine as a source.
4. Run:

   ```powershell
   .\egress-windows-amd64.exe pubkey
   .\egress-windows-amd64.exe install --debug
   ```

   `pubkey` prints the embedded key's public key with no changes. `install`
   copies the binary to its permanent home, writes the two tunnel configs,
   starts `wg0`, extracts the embedded `wstunnel`, creates the
   `egress` scheduled task, points the physical adapter's DNS at
   `127.0.0.1`, and then verifies.
5. If it fails, or if verification is confusing, collect:

   ```powershell
   .\egress-windows-amd64.exe diagnose
   Get-Content C:\ProgramData\egress\egress.log -Tail 120
   ```

   `diagnose` prints the default route, adapter DNS, tunnel service state, the
   scheduled task, listeners on 7103 and 7108, the route pin for
   `152.69.174.7`, a ping through the tunnel, the install directory, and the log
   tail. WireGuard and listener sections need Administrator.
6. Once it works, remove `--debug` from the scheduled task by re-running
   `install` without it. The task is recreated, and the log file stays on disk
   for the next investigation.

The debug log rotates to `egress.log.old` when it passes 5 MB.

## Commands

| Command | What it does |
|---|---|
| `install` | configure this machine (default command) |
| `supervise` | run the resolver and fallback loop; used by the boot service |
| `verify` | check DNS, tunnel, probe and exit address |
| `diagnose` | print platform state: routes, DNS, tunnel services, listeners, probe and log tail |
| `support` | write one archive (summary, diagnose, log tail) with keys and tokens redacted, ready to attach to a message |
| `disable` | stop now, restore DNS, and prevent it from starting at boot; keep configs and logs |
| `enable` | allow it to start at boot again and start it now |
| `remove` | remove every installed part: service, tunnel, DNS settings, configs, wstunnel, logs, installed binary |
| `uninstall` | alias for `remove` |
| `pubkey` | print the public key for a key; changes nothing |

Install flags:

| Flag | Meaning |
|---|---|
| `--key <base64>` | use this private key |
| `--key-file <path>` | read the private key from a file |
| `--ip <addr>` | tunnel address for this device (default `10.88.0.4`) |
| `--no-tunnel` | configure DNS only |
| `--no-fallback` | never start the WebSocket fallback |
| `--split` | accepted for older scripts; split mode is the only mode |
| `--debug` | trace every external command, probe and state change to stderr and the log file |

`disable`, `enable`, `remove` and `uninstall` also accept `--debug`.

Delivery builds made with `build.sh --debug-build` (or `new-device.sh
--debug-build`) log by default, so a first run on someone else's machine
always leaves a log file behind.

The key resolution order is: `--key`, `--key-file`, the key compiled in at build
time, then an interactive prompt.

## How it behaves

- **DNS.** The system resolver points at `127.0.0.1:7103`. The listener accepts
  UDP and TCP, forwards each query as an RFC 8484 POST, and returns the answer
  unchanged. `dns.breadway.dev` is resolved by dialling the default gateway's
  resolver directly, so the bootstrap never depends on the resolver it is
  replacing. No `~dns.breadway.dev` routing domain and no Windows NRPT rule are
  needed.
- **Tunnel.** Linux writes `/etc/wireguard/wg0.conf` with `Table = off`, the two
  half-default routes, and a `PostUp` pin for the Aegis address. Windows writes
  `wg0.conf` and `wg0ws.conf` and switches between
  `WireGuardTunnel$wg0` / `WireGuardTunnel$wg0ws`.
- **Fallback.** The supervisor pings `10.88.0.1` every 15 seconds. Two
  consecutive failures start `wstunnel` and move the endpoint to
  `127.0.0.1:7108`. It resolves `dns.breadway.dev` through the local DoH
  listener rather than the system resolver, and verifies Caddy's certificate.
  Every 10 minutes, and after a network change, it tries the direct endpoint
  again and returns to UDP if the probe answers.
- **IPv6** is not configured by this tool; the tunnel and DNS are IPv4 only.
  Tailscale exit node behaviour is untouched.

## Requirements

| Platform | Requirements |
|---|---|
| Linux | root, systemd, `wireguard-tools`, `ping`. `systemd-resolved` is used when present, otherwise `/etc/resolv.conf` is rewritten and restored on disable or remove. |
| Windows | Administrator, PowerShell, `ping`, `schtasks`, `route`. The signed WireGuard installer and `wstunnel` are embedded. |

On Windows the adapter is pointed at the local DoH listener (`127.0.0.1`) with
the server Windows already had as a secondary, so a stopped, blocked or deleted
resolver degrades to plain DNS instead of leaving the machine with no lookups at
all. The fallback is used whenever the listener does not answer, including when
it is running but cannot reach its upstream, which means a query can leave
unfiltered on a network that blocks the local path. `remove` and `disable` put
the adapter back on DHCP and delete the remembered server. Machines installed
before this change have no fallback entry and fail closed.

On both platforms the `wstunnel` fallback client is extracted from the binary
and verified against a pinned SHA-256 digest; on Windows the WireGuard MSI is
also Authenticode-checked. Linux still needs `wireguard-tools` from its package
manager (kernel WireGuard plus the `wg`/`wg-quick` tools cannot be embedded),
but no GitHub download is required.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `must run as Administrator` | Not elevated. Reopen PowerShell with "Run as administrator". |
| `<user> (HOST\user) is not an administrator of this PC` | The account cannot elevate, so it can never install this. Sign in with an administrator account, or have one run the install; split mode then grants the interactive accounts read and execute on what the per-user proxy needs. Do not add a per-user grant to the install directory: it is SYSTEM and Administrators only so a boot task cannot run a user-writable binary. |
| `Program 'egress.exe' failed to run: Access is denied` | Windows never started the binary, so this is not an egress error. The download is still marked as coming from the internet, or Defender/AppLocker blocks it. Run `Get-ChildItem <folder> | Unblock-File`, confirm `Get-FileHash .\egress.exe -Algorithm SHA256` matches the value in `README.txt`, then retry. On a managed machine an administrator has to allow the file. |
| `must run as root` | Use `sudo`. |
| `WireGuard for Windows is required` | Only a build without the embedded MSI says this. Rebuild with `assets/` present or install WireGuard manually. |
| `... did not start listening` | The supervisor crashed or could not bind 7103. Run `diagnose` and read the log. |
| `wireguard tunnel is down` | The tunnel service failed to install. Check the `diagnose` tunnel-service section and `wireguard.exe` path. |
| `10.88.0.1 does not answer` | The peer is not enrolled, the `/32` does not match `--ip`, or Aegis is not forwarding. Check the public key and `allowed-ips` on Aegis. |
| `exit address is X, expected 152.69.174.7` | Traffic is not entering the tunnel. Same checks as above, plus `AllowedIPs = 0.0.0.0/0` and the route pin. |
| DNS fails but the tunnel is up | The DoH listener is down or the gateway resolver is unreachable. `diagnose` shows the listener and log tail. |
| DNS fails after deleting the install by hand | Install points the adapter at `127.0.0.1:7103`, so removing the files without `remove` leaves the machine with no resolver. Run `deploy/windows-recovery.ps1` from an elevated PowerShell; it clears the tasks, tunnel services, PAC and proxy, puts adapter DNS back on DHCP and drops the pinned routes, all without needing `egress.exe`. |
| Fallback never starts | The embedded `wstunnel` is missing or could not be extracted. Run `diagnose`; check `C:\ProgramData\egress\wstunnel.exe` on Windows or `/usr/local/bin/wstunnel` on Linux. |
| Every page times out on a hostile network | Expected until the first WebSocket switch, which takes roughly 40 seconds (two 15-second probes plus the probe timeouts). |
| `no default route found` | No usable network yet. Connect, then re-run. |
| Re-running `install` changes nothing | `wg0` already exists; the task is recreated and restarted. Use `remove` first for a clean slate. |
| Everything dies after switching networks (WiFi to Ethernet, dock, roam) | The supervisor re-pins on change, fails over across all default routes while probes fail, and engages the fallback on the first failed probe after a change. Give it ~60s after a flip before disabling. |

## Support bundle

`egress support` writes `egress-support-<timestamp>.zip` to the Desktop, or to
`--out <dir>`. It holds a summary (version, platform, install path, split state,
device address and public key), the full `diagnose` output and the last 400 log
lines. Credential-shaped values are replaced before anything is written: labelled
secrets, and bare 44-character WireGuard keys. The device private key is never
included because the bundle reads state, not config files.

## App icon

`assets/egress.ico` is the shield from the site favicon, recoloured to the Bread
palette: `#eab672` stroke on a `#0c0c0c` rounded square with a `#1a1a1a` edge.
It is compiled into the Windows binary through `rsrc_windows_amd64.syso` and
`rsrc_windows_arm64.syso` (generate with `rsrc -ico assets/egress.ico -o
rsrc_windows_<arch>.syso`), which gives Explorer and the taskbar the icon and the
tray loads the same resource instead of the stock application icon.

## Signing Windows builds

`deploy/release.sh` signs every Windows binary with Authenticode when a
certificate is configured, and skips the step otherwise:

```
EGRESS_SIGN_PFX=/path/to/cert.pfx EGRESS_SIGN_PFX_PASS=... ./deploy/release.sh --version 0.4.40
```

Optional: `EGRESS_SIGN_TSA` (RFC 3161 timestamp server, default DigiCert) and
`EGRESS_SIGN_URL`. Each signature is verified with `osslsigncode verify` before
the build is used, and signing runs before the update manifest is published,
because the manifest holds the SHA-256 of the exact bytes we ship.

Authenticode does not replace the update signature: manifests are still signed
offline with Ed25519 and every binary is still checked against that before it is
applied. The two answer different questions, one to Windows and one to us.

Signing `egress.exe` does not sign `wstunnel.exe`, which is a pinned upstream
release extracted at runtime and is the file antivirus usually flags. Until the
fallback client is ours, a Defender detection on that file has to be handled
with a false-positive submission or an exclusion.

## Install reports (automatic tech support)

Every `install` reports home to `https://bypass.breadway.dev/api/report`,
success or failure. The report carries the device public key (matched to the
enrolled peer), OS, arch, build date, the per-check results, and on failure
the `diagnose` output plus the log tail. It carries no secrets. Sending never
fails the install: if the network is down, the report is spooled and the
running supervisor delivers it later.

A failed install rolls back first: the service stops, the tunnel comes down,
and DNS is restored, so the machine is never left offline. The report then
explains what went wrong.

The admin Logins table shows each device's latest report status
(functional, partial, failed, unknown) with a details page per device.

## Updating, disabling and removing

Re-run `install` with the new binary. On Windows the scheduled task is replaced
and restarted; on Linux the unit is rewritten and restarted.

### Turn it off without deleting anything

`disable` stops the resolver and the tunnel now, restores DHCP/system DNS and
the system routes, and stops the service or task from starting at boot. The
configs, log, `wstunnel` and binary stay in place, so `enable` is instant.

```sh
sudo ./egress-linux-amd64 disable
sudo ./egress-linux-amd64 enable
```

```powershell
.\egress-windows-amd64.exe disable
.\egress-windows-amd64.exe enable
```

### Remove everything

`remove` (and its alias `uninstall`) does everything `disable` does, then
deletes the unit or scheduled task, the tunnel configs, the local DNS drop-in,
`wstunnel`, the log and the installed binary. On Linux that includes
`/usr/local/bin/wstunnel` and `/var/log/egress.log`; on Windows it removes
the contents of `C:\ProgramData\egress`.

```sh
sudo ./egress-linux-amd64 remove
```

```powershell
.\egress-windows-amd64.exe remove
```

If you run `remove` from the installed binary itself, Windows cannot delete the
running image. The command says so and leaves that one file behind; delete it
after the command exits. Removing the device from the tunnel also requires
deleting its peer on Aegis, which this tool cannot do from the client.

## Layout

Everything except the entry point lives in `internal/egress`, so the repository
root holds the build scripts, the entry point and the subprojects.

| File | Role |
|---|---|
| `main.go` | entry point; calls `egress.Main()` |
| `internal/egress/main.go` | CLI and install/verify/disable/enable/remove flows |
| `internal/egress/config.go` | constants, key validation, public key, wg config rendering |
| `internal/egress/doh.go` | DoH client and the local UDP/TCP DNS server |
| `internal/egress/supervisor.go` | probe loop and UDP/WebSocket state machine |
| `internal/egress/wstunnel.go` | locate, verify and supervise `wstunnel` (plus pinned download for dev builds without embedded assets) |
| `internal/egress/report.go` | install phone-home report and spooling |
| `internal/egress/verify.go` | install and verify checks |
| `internal/egress/platform_linux.go` | systemd, wg-quick, systemd-resolved, diagnose |
| `internal/egress/platform_windows.go` | WireGuard services, route pin, scheduled task, DNS, embedded installer, diagnose |
| `internal/egress/assets_windows.go` / `assets_linux.go` / `assets_other.go` | embed the per-OS fallback (plus WireGuard MSI on Windows) |
| `internal/egress/debug.go` | `--debug` tracing, log file, diagnose helpers |
| `internal/egress/doh_test.go` | key vector, key/config validation, live UDP and TCP DoH tests |
| `build.sh` / `build.ps1` | link a key into the binary and check it landed |
| `new-device.sh` | pick a free peer address, generate and enroll a key, then build |
| `remove-device.sh` | list registered peers or revoke one by label |
| `publish-device.sh` | upload a device binary to Aegis and register a download login |
| `provision-pending.py` | poll approved applications and provision them automatically |
| `deploy/bypass-provisioner.service` | systemd unit for the provisioner |
| `bypass-server/` | enrollment applications + password-gated downloads (Aegis, Caddy) |
| `dnscloak/` | answer Microsoft names with the relay IP (Aegis, doh-proxy to dnsproxy) |
| `docs/DESIGN.md` | architecture and protocol details |

`go test ./...` runs the local tests, including live requests to the DoH
endpoint. `go test -short ./...` skips the live checks.

## Notes and limits

- The binary cannot enroll itself. Aegis must list the peer before the tunnel
  will handshake.
- The key is a plain string in `.rodata`; `strings` can recover it. Use it as a
  credential, and remove the Aegis peer if it leaks.
- On Windows only the default-route adapter's DNS is changed. If the machine
  switches between Wi-Fi and Ethernet the supervisor re-applies DNS on the new
  default route, but the old adapter keeps its setting until reboot.
- `10.88.0.2` is hermes. Do not reuse it for another device.
- `10.88.0.1` is Aegis and `10.88.0.254` is the Microsoft relay; `new-device.sh`
  never allocates either.

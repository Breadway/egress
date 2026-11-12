# egress design

A single binary that reproduces the hermes bypass on any Linux or Windows
machine that holds an enrolled WireGuard key: DoH on `127.0.0.1:7103`, split
routing through Aegis for destinations proven blocked, and an automatic
WebSocket fallback when UDP is blocked. Routing everything through the tunnel
was removed: it turns a friend's browsing into the relay's bandwidth bill.

Split routing exists on Linux (host routes into wg0), Windows (a per-user
CONNECT proxy and PAC) and macOS (BSD host routes into the tunnel interface).
A build that cannot split is not shipped, because a client with no split path
would either tunnel everything or silently tunnel nothing.

Bandwidth is bounded in three places, all on Aegis:

Aegis's measured uplink is about 67 Mbit/s. The caps are set under it: 30 Mbit
for the WireGuard tunnel, 20 Mbit aggregate for the relay, so roughly a quarter
of the link stays free for everything else.

The owner's own allocation is not part of that tuning: 20 Mbit on the tunnel
and 20 Mbit on the relay.

- `socksrelay --limit-mbps` caps the aggregate relay throughput, shared by
  every connection.
- `socksrelay --limit-mbps-per-user` caps each relay user separately, so one
  leaked build cannot spend the whole cap.
- `deploy/wg-shape.service` shapes the Linux tunnel: 20 Mbit total on wg0 and
  2 Mbit per tunnel address, so no device can take the whole tunnel. It only
  touches traffic inside wg0.

## Shared block table

Devices on the same network share what they learn. The network is identified by
a hash of the SSID (peppered, truncated to 32 hex characters), so the server
stores no plaintext network name. The hash is obfuscation, not secrecy: an SSID
has a small search space.

The table carries two kinds of observation:

- **Domains**: `blocked` or `allowed`, with the probe evidence. Blocked entries
  are merged into a joining device's profile so it does not rediscover a
  filtered domain by probing.
- **Protocols**: outbound `udp`, `tcp`, `dns`, `icmp`, and `quic` reachability,
  so a device joining a UDP-filtered network can start on the WebSocket path
  instead of failing over first. A local measurement always beats a shared one.

Conflicts resolve by verification, and block wins:

1. A device reports the domain blocked.
2. A second device reports it allowed. The entry becomes contested and the
   server asks the allowing device to re-check.
3. The allowing device probes again and posts a final observation. The blocked
   device is then asked to verify.
4. Any blocked answer among the finals keeps the domain blocked; the entry is
   only downgraded when every final says allowed.

Blocked sites are re-verified weekly, per site. The timer starts when the entry
is added and resets on any observation, so a routine probe, a conflict answer
and a fresh sighting all count as verification. The server leases due jobs to
one client at a time (15 minute lease, at most ten per sync), so any client can
do the work without two of them checking the same site.

Entries not seen for 30 days are dropped. Only evidence strings and hashed
network ids are stored; no device identifiers, browsing history, or plaintext
SSIDs.

### Operator controls and visibility

- `split-allow.txt` pins domains direct and `split-block.txt` forces them
  through the tunnel. Both live in the split profile directory and beat
  probing, the shared table and re-checks, so a wrong classification does not
  need a release.
- `disable` and `enable` report their state, so the fleet view does not keep
  showing a stale install.
- The device page keeps the last ten reports, and a healthy device that has
  not reported for three days is shown as stale rather than functional.
- The admin Relay page lists per-device credentials, their relayed volume and
  offers rotate or revoke. The relay reloads its auth file on change, so a
  revocation takes effect within 30 seconds.
- The supervisor starts on the WebSocket path when the stored protocol picture
  says UDP is blocked, instead of failing over first.
- `egress boot on|off` (and the tray) stops egress starting at boot without
  touching the current session. The update check keeps running, so fixes still
  arrive. The preference is stored outside the service, so an update cannot
  silently re-enable it.
- `egress networks list|add|remove|clear` manages an SSID allowlist in
  `networks.txt` next to the per-user proxy state. A missing or empty file
  means any network, and an SSID that cannot be read never blocks, so a laptop
  without a readable WLAN keeps working. On a network that is not listed the
  proxy clears the PAC and stays direct; the tray header shows the current
  network and whether it is allowed.

Relay credentials are per device. `new-device.sh` creates a user:password pair
on the relay and embeds it in that device's build, and `remove-device.sh`
removes the pair along with the peer, so revoking a device stops its relay
access immediately.

No external downloads at install time. The DoH client, the local DNS server, the
fallback supervisor and the key handling are all in the binary. Delivery builds
also embed the pinned `wstunnel` 11.1.0 client for their OS, and Windows builds
additionally embed the signed WireGuard MSI, so the target needs no downloader.
Linux still needs `wireguard-tools` from its package manager. A dev build
without embedded assets falls back to the pinned GitHub download.

## Components

| File | Role |
|---|---|
| `main.go` | CLI, command dispatch, install/verify/disable/enable/remove flows |
| `config.go` | constants, key validation, public-key derivation, wg config rendering |
| `doh.go` | RFC 8484 client plus the UDP/TCP DNS server on 7103 |
| `supervisor.go` | probe loop and UDP/WebSocket state machine |
| `wstunnel.go` | locate, verify and supervise `wstunnel` (plus pinned download for dev builds) |
| `report.go` | install phone-home report and spooling |
| `verify.go` | the checks `install` and `verify` run |
| `platform_linux.go` | systemd, wg-quick, systemd-resolved |
| `platform_windows.go` | WireGuard for Windows services, route pin, scheduled task, netsh/PowerShell DNS, embedded installer |
| `assets_windows.go` | embed the pinned `wstunnel.exe` and WireGuard MSI into Windows builds |
| `assets_linux.go` | embed the pinned `wstunnel` binary into Linux builds |
| `assets_other.go` | keep the shared installer source portable on other builds |
| `embedded.go` | shared checksum-checked extraction of embedded dependencies |
| `debug.go` | `--debug` tracing, log file, `diagnose` output |
| `new-device.sh` | one-shot enrollment and Windows build for a new device |
| `remove-device.sh` | registry-driven peer revocation and local credential cleanup |
| `publish-device.sh` | upload a device binary and register a bcrypt download login |
| `provision-pending.py` | pull approved applications and run new-device + publish |
| `deploy/bypass-provisioner.service` | systemd unit for the pull-based provisioner |
| `bypass-server/` | apply queue, self-set passwords, bcrypt downloads, session admin UI (Aegis loopback :7220; admin via Tailscale Serve :7221) |

## DNS

The system resolver is pointed at `127.0.0.1:7103`. That listener is the binary
itself, not dnscrypt-proxy.

Queries are forwarded as `application/dns-message` POSTs to
`https://dns.breadway.dev/dns-query`. Two details matter:

1. **The bootstrap is in-process.** `dns.breadway.dev` is resolved by dialling
   the default gateway's resolver on port 53, never the system resolver. The
   address is then pinned for the actual TLS connection, and the certificate is
   verified against `dns.breadway.dev`, so a wrong address fails closed.
2. **Because of that, no per-domain routing rule is needed.** dnscrypt-proxy
   needed a `~dns.breadway.dev` routing domain in systemd-resolved, and NRPT on
   Windows, because it asked the system resolver for the bootstrap name. This
   tool does not, so both platforms just set one resolver and nothing else.

If the gateway does not answer, the known Aegis address (`152.69.174.7`) is
used as a seed, so the resolver still comes up on a hostile network.

TCP is served as well as UDP, because resolved retries truncated answers over
TCP.

## Tunnel

Linux writes `/etc/wireguard/wg0.conf` mode 0600 with the private key inline
(`wg-quick` rejects a file path), `Table = off`, the two half-default routes,
and a `PostUp` pin for the Aegis address. That pin is not optional: `152.69.174.7`
falls inside `128.0.0.0/1`, so without it the first handshake is routed into the
tunnel and never arrives.

The endpoint is the literal IP, never a hostname. A hostname would be resolved
by `wg-quick` while the interface is coming up, before networking is necessarily
ready.

Windows has no `wg.exe` and no live `wg set`, so:

- the key is validated and the public key derived in-process with
  `crypto/ecdh` (X25519), not by shelling out;
- two configs are written, `wg0.conf` (direct) and `wg0ws.conf` (relay), and
  switched with `wireguard.exe /uninstalltunnelservice` plus
  `/installtunnelservice`;
- while the relay is in use, `152.69.174.7/32` is pinned to the physical gateway
  with `route add ... metric 1`. WireGuard for Windows only excludes the
  configured endpoint, which is `127.0.0.1` in relay mode, so without this pin
  wstunnel's own connection to Aegis would be routed into the tunnel it carries.

## Fallback

`wstunnel client --http-upgrade-path-prefix wg-tunnel --dns-resolver dns://127.0.0.1:7103 --dns-resolver-prefer-ipv4 --tls-verify-certificate -L udp://127.0.0.1:7108:127.0.0.1:7105 wss://dns.breadway.dev`

The DNS resolver flag matters: on a filtered network the system resolver can
return a sinkhole for `dns.breadway.dev`, while the in-process DoH listener
already knows the real Aegis address. Certificate verification is enabled, so a
wrong address fails closed instead of silently connecting.

The server side already exists on Aegis behind Caddy on 443, so a new device
needs nothing there.

**Health signal is a probe, not the handshake.** While the fallback carries
traffic the handshake stays fresh through it, so handshake age cannot tell a
working UDP path from a rescued one. The supervisor pings `10.88.0.1`.

States:

- **UDP.** Every 15 s, two ping attempts. Two consecutive failures start
  wstunnel, wait for the relay, and move the endpoint to `127.0.0.1:7108`.
  The first failure after a detected network change fails over immediately.
  Every failure is logged with a consecutive count, and route rotation is
  always logged, so the journal shows exactly what the supervisor tried.
  The first failure after a detected network change fails over immediately.
- **WebSocket.** Re-assert the relay endpoint, restart the child if it died, and
  every 10 minutes (or immediately after a network change) move the endpoint
  back to the direct address, probe for 6 s, and either stop wstunnel or restore
  the relay.

The loop polls the default route rather than subscribing to network events, so
one implementation works on both platforms and the boot service needs no
dispatcher script or timer unit.

`wstunnel` is found next to the executable, then on `PATH`, then in the install
directory. Delivery builds embed version 11.1.0 for their OS and extract it to
the install directory after checking a pinned SHA-256 (Linux also chmods it
0755); a dev build without embedded assets downloads the same pinned release
only if it is missing.

The Windows WireGuard MSI is embedded the same way: pinned SHA-256 plus an
Authenticode signer check for WireGuard LLC, then `msiexec /qn /norestart`.
Reinstall stops the old scheduled task and its `wstunnel` child first, because
Windows will not replace a running executable.

## Build and key embedding

`build.sh` (or `build.ps1`) validates a key, derives the public key, and links
the key and tunnel address into the binary:

```
./build.sh --generate --ip 10.88.0.4 --os windows
./build.sh --key-file ~/.keys/device4.key --ip 10.88.0.4 --os linux
```

Linker contract: two package-level string variables in `package main` named
`main.embeddedKey` and `main.embeddedClientIP`, empty in source. `install`
prefers the embedded key over prompting, and the embedded address over the
built-in default. `build.sh` byte-searches the output and fails if the key did
not land, which catches a renamed variable. A third variable,
`main.defaultDebug`, is `"false"` in source; `build.sh --debug-build` sets it
to `"true"`, which makes every command behave as if `--debug` were passed.
There is no opt-out flag: rebuild without it for a quiet binary.

Build tags: the vendor binaries embed only under `-tags delivery`, which
`build.sh` and `build.ps1` always pass. A plain `go build` embeds nothing,
so a clean checkout compiles, vets and tests without the gitignored
`internal/egress/assets/` files; dev builds download the pinned archives instead.

For `--os windows`, the build also requires `internal/egress/assets/wstunnel-windows-amd64.exe`
and `internal/egress/assets/wireguard-amd64-1.1.1.msi` and refuses to build if either is missing
or has the wrong SHA-256. For `--os linux` it requires
`internal/egress/assets/wstunnel-linux-amd64` the same way. `//go:embed` pulls the assets into
the output; a delivery binary is about 20 MB on either platform.

**The binary is a credential.** The key is a plain string in `.rodata` and can
be recovered with `strings`. Do not publish it. If a device is lost, remove its
peer on Aegis and rebuild. Obfuscation is not worth it.

## Debugging

`--debug` traces every external command with its exit code, duration and
output, plus each probe, state transition, endpoint change and DoH bootstrap.
Output goes to stderr and to a log file, because the Windows service runs
detached:

- Linux: `/var/log/egress.log`
- Windows: `C:\ProgramData\egress\egress.log`

`egress diagnose` prints routing, adapter DNS, tunnel services, the
scheduled task, listeners, the route pin, a probe, the install directory and the
last 60 log lines on Windows. The Linux build prints the default route, resolver
status, WireGuard state, listeners, a probe, the wstunnel path and the log tail.
It is read-only and needs no special order.

## Lifecycle

Three commands share one teardown path:

- **disable** stops `egress.service` / the `egress` task, stops
  `wg-quick@wg0` / both tunnel services, removes the Windows route pin, and
  restores resolver settings. Linux removes the resolved drop-in and restarts
  `systemd-resolved`, or restores `/etc/resolv.conf.egress.bak`. Windows
  resets the default-route adapter with `-ResetServerAddresses`. Configs,
  `wstunnel`, the log and the binary stay.
- **enable** re-enables the unit or task and starts it. The supervisor
  re-applies DNS at startup, so DNS is correct immediately rather than after the
  first 60-second check. DNS-only installs (`--no-tunnel`) run a resolver-only
  watchdog with the same startup and periodic re-apply, so DHCP renews cannot
  silently drop protection.
- **remove** (alias `uninstall`) runs disable, deletes the unit or task, the
  tunnel configs, the resolved drop-in, `wstunnel`, the log (including the
  rotated copy) and the canonical installed binary. Windows empties
  `C:\ProgramData\egress`; a binary that is executing cannot be unlinked,
  so it is named in the output instead.

Disable restores DHCP/automatic DNS rather than a saved copy of the previous
resolver, because the previous value is network-specific and may be stale by the
time the tool is turned off.

## Failure handling

| Case | Behaviour |
|---|---|
| No key given | DNS only, tunnel untouched, exit 0 |
| Key malformed | refuse before changing anything, exit 1 |
| DoH listener will not start | install fails with a pointer to `diagnose` |
| Verification fails | networking rolls back to pre-install state, then a failure report goes home; exit non-zero |
| Foreign wg0 already exists (NetworkManager autoconnect, another tool) | install replaces it after confirming our peer is absent; never touches an interface carrying our peer |
| Default route changes after bring-up (roam, dock, tether) | the supervisor re-pins the Aegis address via the new gateway on every detected change, on all platforms; while probes keep failing it walks all default routes so one dead interface cannot strand tunnel, DNS and fallback together |
| UDP blocked | switch to WebSocket automatically; not an error |

## Install reports

`install` ends with a phone-home report to `/api/report` on
`bypass.breadway.dev`, whether it passed or failed. The payload is the device
public key (matched server-side to the enrolled peer), OS/arch/build date,
structured check results, and on failure the error plus captured `diagnose`
output and log tail. No secrets are sent. Delivery is best effort with an
Aegis-direct fallback for poisoned resolvers; unsent reports spool to disk
and the supervisor flushes them. The server keeps the latest report per peer
(20/hour per IP) and the admin Logins table shows functional, partial,
failed, or unknown with a per-device details page.

## Enrollment

The tool cannot enroll itself. Aegis must already list the client's public key
as a peer with a unique `/32`, and the tool prints the public key so it can be
added before first use. `10.88.0.2` is hermes; every other device needs its own
address (the default is `10.88.0.4`).

`new-device.sh` automates the whole step from a machine with SSH and
passwordless sudo to Aegis: it reads the live peers and `wg0.conf`, picks the
lowest free `/32`, generates and saves the key, appends the peer and applies it
with `wg set`, then runs `build.sh --quiet`. The private key is written to
`~/.keys` and never printed. Each successful device is recorded in the local,
mode-0600 TSV registry `~/.keys/egress-peers.tsv`. `remove-device.sh
--name <label>` uses that record to back up Aegis's config, remove precisely
the generated peer block and live peer, then remove the record and the local
key/binary. `remove-device.sh --list` is the peer inventory.
`publish-device.sh --name <label>` uploads the built binary to Aegis and
registers a username + generated password for it at
`https://bypass.breadway.dev/download`, so the file itself never has to be
sent. With `--application <id>` it also links the applicant's status page to
the new login, so the applicant finds the issued login, password, and a one-click
download link there instead of receiving credentials second-hand. Applications from `/apply` (name + why, no contact info) queue
on Aegis for review in the session-based admin UI. The admin UI is tailnet-only
through Tailscale Serve on :7221; the public host returns 404 for `/admin*`.

Applications record the requested OS (Windows or Linux). Approving one queues
it for `provision-pending.py` on hermes. The provisioner pulls the tailnet-only
admin API (`/admin/api/pending`, `/admin/api/claim`, `/admin/api/release`),
claims one application, runs `new-device.sh --os <os>` and
`publish-device.sh --application <id> --os <os>`, and repeats. Claims
expire after 15 minutes so a crashed provisioner does not strand a job. A
failed job is parked with an error in the admin UI and retried only when the
admin presses Retry. Aegis never initiates into the home network; hermes is
the only side that connects out. See `bypass-server/` and
`deploy/bypass-provisioner.service`.

## Platform notes

- Linux: `wg-quick@wg0` and `egress.service` are separate units; the
  supervisor only moves the endpoint.
- Windows: a scheduled task (`egress`, `onstart`, `SYSTEM`, highest
  privilege) runs `supervise`. The tunnel services are
  `WireGuardTunnel$wg0` / `WireGuardTunnel$wg0ws`.
- The install directory on Windows is restricted to SYSTEM and Administrators
  by SID in every install mode, including `--no-tunnel`, because it always
  holds the installed binary whose embedded key is recoverable with strings.
  Restriction failures fail the install rather than passing silently, and
  `diagnose` prints the directory ACL.
- `wstunnelSums` pins the GitHub archives for `linux/amd64` and `windows/amd64`
  for dev builds without embedded assets. Delivery builds never download:
  they extract the embedded binary after checking its own SHA-256. Another
  platform needs either a pinned checksum row plus an `assets_*.go` embed, or a
  manual `wstunnel` install.

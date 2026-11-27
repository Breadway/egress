# Exits, and the local page

A filtered network pushes blocked destinations into the tunnel. Those leave
through Aegis by default, which is a cloud address, and some sites answer a
cloud address with a block page. reddit is the example: `403 blocked by network
security` from Aegis, `200` from hestia's home connection.

Two pieces handle that:

- **`egress-exit`** runs on Aegis and chooses which exit carries which
  destination.
- **The local page** runs on each client and explains, per blocked site,
  whether it is being reached and through which exit.

## Exits

An exit is any host that dials Aegis as an ordinary `wg0` peer, forwards
`10.88.0.0/24` back, and NATs it out its own uplink. hestia is the first one.
Nothing about an exit is hardcoded: the operator enrolls it in a registry.

```
client -> wg0 -> Aegis -> the exit that serves the destination -> internet
```

All exits share `wg0`, so an exit needs no new inbound port on Aegis and works
behind NAT. WireGuard picks the peer from the destination prefix, so each exit
carries only the prefixes assigned to it. `wg0.conf` sets `Table = off`, which
keeps an exit's `0.0.0.0/0` mapping from installing a default route; the routes
are managed by the router.

An exit can also be the target of a DNAT from the hub, not only the owner of a
prefix. The router keeps the exit's tunnel address (`address` in the registry,
for example `10.99.0.2`) in the peer's allowed IPs, so the hub can redirect a
destination straight to the exit's own address. The Hestia relay uses this: the
hub DNATs the fake Microsoft address and the Cloudflare ranges to the exit's
`10.99.0.2:7106`, and the exit resolves the real host from the TLS SNI.

Allowed IPs are rebuilt from `state.json` every cycle, so a learned prefix is
runtime state. A restart re-adds the current assignments and the learner
re-derives anything still missing on the next cycle.

### Registry

`/var/lib/bypass/exits.json`, owned by `bypass` so the web admin can flip the
enabled flag:

```json
{"version": 1, "exits": [
  {"id": "hestia", "label": "hestia", "pubkey": "...", "enabled": true,
   "priority": 10, "max_prefixes": 200, "host": "hestia"}
]}
```

`network` is optional: when the exit also runs as a client, its network id lets
the router skip it for domains that network already reports blocked. The active
probe still decides.

### Enroll and remove

```sh
./deploy/add-exit.sh --id hestia --host hestia [--priority 10] [--network <id>]
./deploy/remove-exit.sh --id hestia
```

`add-exit` keeps the private key on the exit host, writes its `wgexit.conf`,
adds the peer to `wg0.conf` (a backup first, never restarting `wg0`), registers
it, and verifies the handshake. `install-exit.sh` installs the router itself:

```sh
./deploy/install-exit.sh
./deploy/add-exit.sh --id hestia --host hestia
```

The web admin has an **Exits** page: health, handshake age, carried prefixes,
served sites, routed prefixes, unserved names, and enable/disable buttons.

## How the router decides

Every cycle (ten minutes) it:

1. Reads the fleet's shared block table for candidate domains.
2. Probes each one over the **cloud exit**, on a marked socket that leaves
   through the physical link, so a learned route can never make the cloud check
   follow an exit.
3. If the cloud serves the site, releases its prefixes.
4. Otherwise keeps the current exit if it is healthy and still serves the site.
5. Otherwise tries the enabled exits in priority order, skipping any whose own
   network reports the domain blocked, and assigns the site's `/24`s to the
   first one that serves it.
6. If none serve it, releases the prefixes and marks the site **unserved**.

Health is the WireGuard handshake: an exit with no handshake in five minutes is
not a candidate. When an exit comes back, the unserved backoff is cleared at
once. Unserved names are retried every thirty minutes; the cloud check still
runs every cycle, so a site that stops refusing the cloud exit is released
immediately.

Guards: per-exit prefix cap (default 200), global cap (800), no chaining (an
exit never becomes a client of another exit), and certificate-name mismatches
are not treated as refusals.

State is in `/var/lib/egress-exit/state.json`; the published status is
`/var/lib/egress-exit/status.json` (0644, no secrets). The learner re-reads the
kernel every cycle, so a `wg0` restart cannot silently drop a route.

### Client DERP path

The split feed also carries the exit list and the router's assignments. A
client keeps learning blocked sites as it does today. When a learned site is
assigned to a residential exit, the client sends only those destinations to
that exit over the existing DERP transport and leaves every other blocked
destination on the cloud exit. A site the router has not assigned yet stays on
the cloud exit and moves on the next feed once the router has probed it, so the
path is learned rather than static.

An exit registers with `transport: derp`, its `relay_key`, and the WireGuard
key of the interface that carries the traffic (`derp_pubkey`). On the exit host,
`egress exit serve --derp` publishes the relay key, adds clients that announce
use, and forwards their packets through the local WireGuard listener:

```sh
egress exit serve --derp
```

The unit is `deploy/egress-peer-exit.service`. The DERP relay itself is the
existing Tailscale relay used by the other DERP paths; this path changes which
exit carries the traffic, not the relay.

### Failure behaviour

- Exit gone: its prefixes move to the next exit that serves them, within one
  cycle (or as soon as the handshake is stale).
- Every exit gone: blocked sites stay on the cloud exit and are marked
  unserved, and the admin page says every exit is unreachable.
- `egress-exit` down: routes persist in the kernel; a restart restores them.

## The local page

`http://127.0.0.1:7280/`, served by the client's own supervisor.

- Each blocked site says **via `<exit>`**, **cloud exit**, or **no path**.
- It answers when the tunnel is down; the banner says egress is offline and the
  table is the last known state.
- Open it from the tray (**Why is this blocked?**) or with `egress portal`.
- `egress portal --print` prints the URL without opening a browser.

The feed carries `served_by` and `unserved` per domain, so the page reflects the
router's decisions without asking Aegis at page load time.

There is no certificate authority in this design: the browser still shows its
own error page for an unserved HTTPS site, and this page is where the
explanation lives. A browser-injected page would require a device-local CA and
is deliberately not implemented.

## Relay credentials and the admin page

Per-device relay credentials live in `/etc/egress-socks/auth`. The relay runs as
`egress-socks` and the admin server runs as `bypass`, so the directory has to be
traversable by the server even though the file is not:

```
/etc/egress-socks        0751 root:egress-socks
/etc/egress-socks/auth   0640 bypass:egress-socks
```

With the directory at `0750` the Relay page reports `permission denied` on a
file whose own mode looks correct, because the server cannot traverse the
directory to reach it. Rotating or revoking from the page writes the file as
`bypass`, which is why the server owns it.

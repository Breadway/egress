# egress GUI API (v1)

The GUI is a user-level frontend. The egress daemon remains the only component
that owns the tunnel, routes, exits and updates. The GUI talks to a small local
API and never reads root-owned state directly.

## Transport and authentication

- Loopback HTTP at `http://127.0.0.1:7280/api/v1`, on the same listener as the
  local portal.
- The daemon writes a random token to a file the signed-in user can read while
  the daemon itself runs as root or SYSTEM:
  - Linux: `/run/egress/api-token`
  - Windows: `%ProgramData%\egress-gui\api-token` (inherits the Users read ACE
    from ProgramData; the administrator-only install directory is not used)
  - macOS: `/usr/local/var/run/egress/api-token`
  - `EGRESS_API_TOKEN_FILE` overrides all of them (tests, a second identity)
- The Tauri shell resolves the same path through the `api_token` command and
  adds `Authorization: Bearer <token>` to every request.
- The file is mode 0644 by design: the API is loopback only and the alternative
  is a root prompt on every GUI launch. A Unix socket with peer credentials is
  the planned upgrade; the JSON contract does not change.
- All responses are JSON. Errors use an HTTP status and:
  `{"error":{"code":"...","message":"..."}}`.
- CORS is open on the loopback listener. The bearer token is the boundary, not
  the origin.
- The API has no arbitrary command execution. Only the actions listed here are
  allowlisted.

## `GET /status`

```json
{
  "version": "0.4.105",
  "online": true,
  "connected": true,
  "connected_since": "2026-11-21T12:00:17+08:00",
  "mode": "automatic",
  "path": "direct",
  "exit": "Charon",
  "speed_mbps": 20.0,
  "data_gb": 1.9,
  "unblocked_today": 42,
  "circle_online": 3,
  "network": "home|192.168.1.1"
}
```

- `mode`: `automatic` or `direct` (from settings).
- `path`: `direct`, `cloud`, `off`. It is `off` while paused. A peer exit is
  represented by `exit`; `path` describes the transport to the cloud relay.
- `exit`: `Cloud relay`, or the circle member currently carrying blocked
  traffic. Never a key or tunnel address.
- `speed_mbps` and `data_gb` come from the tunnel interface counters on Linux.
  Other platforms report zero until a counter source is added.
- `unblocked_today` is the current blocked-site set, not a midnight rollover.

## `POST /connection`

```json
{ "connected": false }
```

Pauses or resumes protection. Pausing stops the WireGuard interface but keeps
the service, resolver, portal and this API running, so reconnecting never needs
elevation or a service restart. Returns the new `Status`.

## `GET /circle`

```json
{
  "circle": "bread",
  "people": [
    {
      "id": "self",
      "name": "bos",
      "kind": "device",
      "online": true,
      "sharing": false,
      "transport": "direct",
      "last_seen": "",
      "self": true
    }
  ]
}
```

- `kind`: `device` or `friend`.
- `transport`: `direct`, `relay` or `offline`.
- `sharing` means that person's connection is carrying blocked traffic for
  this device.
- No public keys, tunnel addresses or raw endpoints are exposed.

## `GET /protection`

```json
{
  "stats": { "unblocked": 42, "via_friend": 30, "via_cloud": 12, "retry": 0 },
  "sites": [
    {
      "domain": "speed.cloudflare.com",
      "via": "friend",
      "label": "Hestia",
      "at": "2026-11-21T12:00:00Z",
      "retry": false
    }
  ]
}
```

`via`: `friend`, `cloud`, `direct` or `none`. `label` is the display name the
UI prints. `at` is the last probe time, newest first. `retry` is true when the
site could not be served.

## `POST /protection/retry`

```json
{ "domain": "2.arch.pool.ntp.org" }
```

Queues one verification attempt for a site already in the blocked list. Returns
`{"ok":true}` or 404.

## `GET /activity?limit=50`

```json
{
  "events": [
    {
      "time": "2026-11-21T12:04:11+08:00",
      "kind": "friend",
      "title": "Charon is now helping with your connection",
      "detail": "relayed through their internet"
    }
  ]
}
```

`kind`: `connection`, `friend` or `protection`. Newest first. Events are derived
from real transitions (connection, path, exit, peer links, newly served sites),
collapsed when the same title repeats within two minutes, and persisted to
`gui-activity.json` in the daemon state directory. The ring holds 200 rows.

## `DELETE /activity`

Clears the local activity ring and its persisted file. Returns `{"ok":true}`.

## `POST /protection/report`

```json
{ "domain": "example.com" }
```

Queues a first probe for a site the user could not open. A confirmed block joins
the profile the same way a learned one does. Returns `{"ok":true}`; a malformed
or non-hostname value returns 400.

## `GET /settings` and `PATCH /settings`

`GET` returns:

```json
{
  "connect_automatically": true,
  "relay_fallback": true,
  "relay_region": "automatic",
  "share_connection": false,
  "share_scope": "friends",
  "share_limit_gb": 50,
  "hide_public_address": false,
  "relay_only": false,
  "share_reports": true,
  "notify_friend": true,
  "notify_site": false,
  "notify_drop": true,
  "text_size": "comfortable",
  "mode": "automatic"
}
```

`PATCH` accepts any subset and returns the saved set. The daemon applies every
field that has a backend:

- `connect_automatically` enables or disables the boot service.
- `relay_fallback` toggles the WebSocket fallback in the supervisor.
- `mode: "direct"` also forbids the fallback.
- `share_connection`, `share_scope` and `share_limit_gb` start or stop this
  device's exit server (Linux only; other platforms store the preference).
  Serving always uses the relay, never a public listener. `scope: "none"`
  stops serving even when sharing is on. The limit is counted from WireGuard
  transfer counter deltas, persisted in `share-usage.json` with the per-peer
  baselines, and resets at the start of each month without charging the
  previous month's counters again. Reaching it withdraws the exit until the
  next month.
- `hide_public_address` and `relay_only` stop direct peer links, so friends
  reach this device through the relay or the Aegis star.
- `share_reports` controls outbound blocked-site learning. Turning it off keeps
  the circle's incoming learning working.
- `relay_region` selects the DERP region (`sydney` = `syd`,
  `singapore` = `sin`, `los_angeles` = `lax`, `automatic` = the built-in
  default). It is read when the relay connection starts, so a change applies on
  the next service start.
- `notify_*` are read by the desktop app, which raises native notifications
  through Tauri. The daemon does not notify.

The API does not restart the service.

## `GET /events` (server-sent events)

Live stream for Home and Activity. Send the bearer token as a header (the GUI
uses `fetch`, not `EventSource`).

```
event: status
data: { ...same shape as GET /status... }

event: activity
data: { ...same shape as one activity row... }
```

Status is sent every two seconds and on connect. The GUI falls back to polling
every five seconds if the stream is unavailable, and reconnects when the daemon
restarts.

## Desktop admin proxy

The desktop admin section uses these local endpoints. They require the normal
local bearer token and an additional `X-Admin-Token` header. The daemon
forwards to `https://bypass.breadway.dev/admin/api` over the tunnel and never
stores the admin token.

- `GET /admin/overview`
- `GET /admin/applications`
- `GET /admin/devices`
- `POST /admin/application` with `id` and `action` (`approve`, `reissue`, `delete`)
- `POST /admin/device` with `action` (`invite`, `revoke`) and `label`/`id`

The web admin stays available as the fallback. List responses omit invite
tokens and password hashes; a newly created invite returns its token once.

## Versioning

The path carries `v1`. Additive fields are allowed. Removing or changing the
meaning of a field requires `v2`.

## Implementation status

Implemented in the daemon and wired into all five screens. The GUI keeps demo
data only as a first-launch fallback when the API cannot be reached.

- Connection pause/resume, site retry and reporting, activity clearing, boot
  start, relay fallback, sharing, address hiding and relay region all have real
  backends.
- Native notifications are raised by the Tauri shell from the settings flags.
- The relay region applies on the next service start, the only setting that
  does not take effect immediately.

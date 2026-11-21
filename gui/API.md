# egress GUI API (v1)

The GUI is a user-level frontend. The egress daemon remains the only component
that owns the tunnel, routes, exits and updates. The GUI talks to a small local
API and never reads root-owned state directly.

## Transport and authentication

- Loopback HTTP at `http://127.0.0.1:7280/api/v1`, on the same listener as the
  local portal.
- The daemon writes a random token to a file for the local user:
  - Linux: `/run/egress/api-token`
  - other platforms: the temp directory, `egress-api-token`
  - `EGRESS_API_TOKEN_FILE` overrides both (tests, a second identity)
- The Tauri shell reads that file through the `api_token` command and adds
  `Authorization: Bearer <token>` to every request.
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

- `mode`: `automatic`, `direct`, `friend` (from settings).
- `path`: `direct`, `relay`, `cloud`, `off`. It is `off` while paused.
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
- The active peer exit is included even when it is not in the published peer
  list, so the Home screen can name who is helping.
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

## `GET /settings` and `PATCH /settings`

`GET` returns:

```json
{
  "connect_automatically": true,
  "smart_routing": true,
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

`PATCH` accepts any subset and returns the saved set. The daemon applies what it
can today:

- `connect_automatically` enables or disables the boot service.
- `relay_fallback` toggles the WebSocket fallback in the supervisor.
- `mode: "direct"` also forbids the fallback.

The rest are persisted for the screens that own them. Sharing activation still
runs through the existing exit-serve path, and region, address hiding and
notifications are stored until their backends are wired. The API does not
restart the service.

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

## Versioning

The path carries `v1`. Additive fields are allowed. Removing or changing the
meaning of a field requires `v2`.

## Implementation status

Implemented in the daemon and wired into all five screens. The GUI keeps demo
data only as a first-launch fallback when the API cannot be reached. Remaining
backend work: sharing activation, relay region selection, address hiding and
native notifications.

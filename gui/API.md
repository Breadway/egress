# egress GUI API (v1)

The GUI is a user-level frontend. The egress daemon remains the only component
that owns the tunnel, routes, exits and updates. The GUI talks to a small local
API and never reads root-owned state directly.

## Transport and authentication

- Loopback HTTP at `http://127.0.0.1:7280/api/v1`, on the same listener as the
  local portal.
- The daemon writes a random token to its state directory, readable by the
  local user. Requests carry `Authorization: Bearer <token>`.
- A Unix socket or named pipe with filesystem ACLs is the preferred next
  revision. The JSON contract does not change.
- All responses are JSON. Errors are JSON with an HTTP status:
  `{"error":{"code":"...","message":"..."}}`.
- The API never exposes arbitrary command execution. Every action is an
  allowlisted operation.

## `GET /status`

```json
{
  "version": "0.4.105",
  "online": true,
  "connected": true,
  "connected_since": "2026-11-21T07:12:14Z",
  "mode": "automatic",
  "path": "relay",
  "exit": "Hestia",
  "speed_mbps": 20.0,
  "data_gb": 1.2,
  "unblocked_today": 58,
  "circle_online": 5,
  "network": "home"
}
```

`mode`: `automatic`, `direct`, `friend`. `path`: `direct`, `relay`, `cloud`,
`off`.

## `POST /connection`

```json
{ "connected": false }
```

Asks the supervisor to stop or start the tunnel. Returns the new `Status`.
Starting the tunnel may require elevation; the daemon handles that prompt
through the platform service, not the GUI.

## `GET /circle`

```json
{
  "circle": "bread",
  "people": [
    {
      "id": "hestia",
      "name": "Hestia",
      "kind": "friend",
      "online": true,
      "sharing": true,
      "transport": "relay",
      "last_seen": "2026-11-21T10:25:00Z",
      "self": false
    }
  ]
}
```

`kind`: `device` or `friend`. `transport`: `direct`, `relay` or `offline`.
`self` marks the device the GUI is running on. No public keys, tunnel
addresses or raw endpoints are exposed to the user UI.

## `GET /protection`

```json
{
  "stats": { "unblocked": 58, "via_hestia": 36, "via_cloud": 21, "retry": 1 },
  "sites": [
    {
      "domain": "speed.cloudflare.com",
      "via": "hestia",
      "at": "2026-11-21T10:25:00Z",
      "retry": false
    }
  ]
}
```

`via`: `hestia`, `cloud`, `direct` or `none`.

## `POST /protection/retry`

```json
{ "domain": "2.arch.pool.ntp.org" }
```

Queues one verification attempt. Returns `{"ok":true}`.

## `GET /activity?limit=50`

```json
{
  "events": [
    {
      "time": "2026-11-21T10:25:00Z",
      "kind": "friend",
      "title": "Hestia is now helping with your connection",
      "detail": "relayed through their home internet"
    }
  ]
}
```

`kind`: `connection`, `friend`, `protection`.

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
  "text_size": "comfortable"
}
```

`PATCH` accepts any subset of those fields and returns the resulting settings.
Changing connection-affecting fields applies on the next reconcile; the API
does not restart the service.

## `GET /events` (server-sent events)

Optional live stream for the Home and Activity screens.

```
event: status
data: { ...same shape as GET /status... }

event: activity
data: { ...same shape as one activity event... }
```

The GUI falls back to polling `GET /status` every 5 seconds if the stream is
unavailable.

## Versioning

The path carries `v1`. Additive fields are allowed. Removing or changing the
meaning of a field requires `v2`.

## Implementation status

This document defines the contract. The GUI is currently built against mock
data (`frontend/src/lib/data/mock.ts`) while the daemon endpoints are added.
The TypeScript types in `frontend/src/lib/api/types.ts` are the shared shape.

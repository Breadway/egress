# egress GUI

The user-facing desktop app for egress. It shows whether you are protected, who
is in your circle, which sites were unblocked, and the settings that control
connection and sharing.

This is not an operator console. It never exposes relay keys, peer IDs, tunnel
addresses or DERP terminology. The daemon is still the only component that owns
the tunnel.

## Stack

- Tauri 2 (Rust shell, tray icon, native window)
- SvelteKit 2 with Svelte 5 runes, TypeScript, Vite
- `adapter-static` in SPA mode (`ssr = false`, `index.html` fallback)
- Bread design tokens in `frontend/src/lib/theme.css`: Varela Round, the BOS
  dark base (`#0c0c0c`), bread accent (`#eab672`), 8 px cards, 6 px inputs and
  pill badges

```
gui/
  API.md                 local daemon API contract
  frontend/              SvelteKit app
    src/routes/          Home, Friends, Protection, Activity, Settings
    src/lib/components/  Sidebar, Topbar, Statusbar, Icon, Toggle, Toast, Sparkline
    src/lib/api/         typed client and shared types
    src/lib/data/        fallback data before the daemon answers
  src/                   Tauri crate
    src/lib.rs           window, tray, close-to-tray
    tauri.conf.json      window, CSP, bundle
    capabilities/        main-window permissions
    icons/               generated from ../../assets/egress.png
```

## Install

The desktop app is a bakery-channel package:

```sh
bakery install egress-gui
```

It needs the egress daemon installed and enrolled on the machine. The daemon
owns the tunnel, and the app reads its local API.

## Development

```sh
cd gui/frontend
npm install
npm run dev          # Vite on http://localhost:1420
```

Run the full desktop app (starts Vite through Tauri):

```sh
cd gui/src
cargo tauri dev
```

Checks and a production build:

```sh
cd gui/frontend
npm run check
npm run build
```

The built site is written to `gui/frontend/build`, which is what
`frontendDist` points at.

## Data

Every screen reads the live daemon API through `frontend/src/lib/api/client.ts`
and the single store in `frontend/src/lib/state/app.svelte.ts`. `API.md` is the
contract and `frontend/src/lib/api/types.ts` is the shared shape.

The daemon writes a bearer token to `/run/egress/api-token` on Linux,
`%ProgramData%\egress-gui\api-token` on Windows, or
`/usr/local/var/run/egress/api-token` on macOS (or `EGRESS_API_TOKEN_FILE`).
The Tauri shell reads it through the `api_token` command. For a plain browser
during development, set `VITE_EGRESS_TOKEN` and optionally `VITE_EGRESS_API`:

```sh
VITE_EGRESS_TOKEN=$(cat /run/egress/api-token) npm run dev
```

The store starts on `frontend/src/lib/data/mock.ts` so the window renders before
the daemon answers, then replaces it with live status, circle, protection,
activity and settings. The sidebar footer shows "Demo data" while the fallback
is in use.

## Design reference

`../design/gui-mockup.html` (and its PNG) is the approved mockup the screens
were ported from.

## Status

- Home, Friends, Protection, Activity and Settings are ported and live.
- The daemon serves `/api/v1/status`, `/connection`, `/circle`, `/protection`,
  `/protection/retry`, `/protection/report`, `/activity` (GET and DELETE),
  `/settings` and the `/events` stream.
- Connection control pauses and resumes the tunnel without restarting the
  service. Site retry, reporting and settings persistence are wired.
- Sharing starts and stops a real exit server on Linux, with the monthly limit
  enforced and persisted. Address hiding and relay-only stop direct peer links.
  Relay region selects the DERP region on the next service start. Native
  notifications use the Tauri notification plugin.

`npm audit` reports advisories against SvelteKit 2 that are only fixed in
SvelteKit 3. They cover server-side form actions, prerendered cache headers and
remote functions. This app is a static SPA with no server, no form actions and
no prerendered pages, so none of them apply. Revisit at the SvelteKit 3
upgrade.

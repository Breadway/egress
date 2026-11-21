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
    src/lib/data/        mock data until the daemon endpoints land
  src/                   Tauri crate
    src/lib.rs           window, tray, close-to-tray
    tauri.conf.json      window, CSP, bundle
    capabilities/        main-window permissions
    icons/               generated from ../../assets/egress.png
```

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

Every screen reads through `frontend/src/lib/data/mock.ts` while the daemon
endpoints are being added. `API.md` is the contract, and
`frontend/src/lib/api/types.ts` is the shared shape. Switching to live data
means calling `frontend/src/lib/api/client.ts` instead of the mock module.

The GUI talks to `http://127.0.0.1:7280/api/v1` with a bearer token written for
the local user by the daemon. The Tauri CSP already allows that origin.

## Design reference

`../design/gui-mockup.html` (and its PNG) is the approved mockup the screens
were ported from.

## Status

- Home, Friends, Protection, Activity and Settings are ported.
- Remaining: daemon `/api/v1` endpoints, then replacing mock data.

`npm audit` reports advisories against SvelteKit 2 that are only fixed in
SvelteKit 3. They cover server-side form actions, prerendered cache headers and
remote functions. This app is a static SPA with no server, no form actions and
no prerendered pages, so none of them apply. Revisit at the SvelteKit 3
upgrade.

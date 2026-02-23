# Frontend design (ProbeScout)

Product name: **ProbeScout**. See [product-name.md](product-name.md).

## Purpose

Single-screen UI: user enters target (IP or domain), starts scan with one button, and sees live status and per-stage nmap output. All logic and decisions live in the backend; frontend only displays API state.

## Stack

- **Node.js** (Vite for dev server and build).
- Vanilla JS, HTML, CSS (no framework) to keep the surface minimal and aligned with “view only”.

## API contract (frontend ↔ backend)

Base URL: configurable (default `http://localhost:12001`; see port_registry.yaml). All requests to `/api/*`. Frontend dev server: port 12000.

| Method | Path | Request | Response (success) |
|--------|------|---------|---------------------|
| POST   | `/api/scan` | `{ "target": "hostname-or-ip" }` | `{ "scan_id": "uuid", "status": "running" }` |
| GET    | `/api/scan/status` | — (single active scan) or `?scan_id=...` | See status response below |

**Status response** (GET /api/scan/status):

- `scan_id`, `target`, `status` (`idle` \| `running` \| `done` \| `error`).
- `step`: current step number.
- `current_action`: current or last `action_id` (e.g. `host_reachability`, `port_scan_1_100`).
- `stages`: array of `{ "action_id", "label", "output", "done" }` — one entry per nmap (or wait) stage; `output` is backend-provided text (e.g. nmap stdout summary or raw).
- `error`: present if `status === "error"`.

Frontend polls status while `status === "running"` (e.g. every 1–2 s). No scan logic in frontend; only render state and stages from this payload.

## UI layout

1. **Target input** — Single text field, placeholder “IP or hostname”. No validation of format in frontend (backend validates).
2. **Execute button** — Starts scan (POST /api/scan). Disabled while no target or while status is `running`.
3. **Status box** — Section below showing:
   - Current status line: “Idle” / “Running – step N” / “Done” / “Error: …”.
   - List of **stages**: for each stage, show label (e.g. “Host reachability”, “Port scan 1–100”) and the `output` text in a fixed-height scrollable block. Current/running stage can be visually highlighted.

## Data flow

1. User types target, clicks Execute.
2. Frontend POSTs `{ target }` to `/api/scan`. On success, sets local “running” and starts polling.
3. Poll GET /api/scan/status until `status` is `done` or `error`. Render `step`, `current_action`, and `stages` in the status box.
4. On `done` or `error`, stop polling; keep last state visible.

## File layout (frontend)

- `index.html` — Single page, root div for app.
- `src/main.js` — Fetch, polling, DOM updates (no business logic).
- `src/style.css` — Layout and status box styling.
- `vite.config.js` — Dev server on port 12000, proxy `/api` to backend on port 12001.
- `package.json` — Scripts: `dev`, `build`, `preview`.

## Startup

`dev/app/frontend/startup_frontend.sh` runs `npm install` (if needed) and `npm run dev` (frontend on port 12000). Backend base URL via env (e.g. `VITE_API_ORIGIN`) or default `http://localhost:12001`.

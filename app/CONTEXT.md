# ProbeScout — project context

**Read this first** when opening this repo in Cursor (or after moving the project). This file is the single place for project identity, paths, and where things live.

## Project root (after your move)

- **Base path:** `/home/vlabs/tensor42/t42/probescout/development`
- You open Cursor with this directory as the workspace. All paths below are relative to this root.

## Product

- **Name:** ProbeScout
- **What it is:** AI-driven, bounded single-target reconnaissance (nmap). Backend owns all decisions and scan logic; frontend is view-only (target input, Execute, status/stages from API).

## Directory layout

Everything lives under **`dev/app/`**. Backend and frontend are under app.

| Path | Purpose |
|------|--------|
| `dev/app/backend/` | All backend code. Python, RestAPI. Config, agent loop, nmap runner, guardrails. |
| `dev/app/frontend/` | All frontend code. Node.js (Vite), single screen: target, Execute, status box. |
| `dev/app/backend/harness_rules/` | Backend rules: MOTHER.md, md-files-location, conventions, backend-authority. Cursor follows these in backend. |
| `dev/app/frontend/harness_rules/` | Frontend rules: MOTHER.md, md-files-location, conventions. Cursor follows these in frontend. |
| `dev/app/backend/docs/` | Implementation spec: implementation_design.md, PRODUCT_DESIGN.md. Single source of truth for behavior. |
| `dev/app/wiki/docs/` | All other .md documentation (product-name, frontend-design, etc.). New docs go here. |
| `dev/app/.cursor/rules/` | Cursor rules for the app (mother, project-structure). |

## Rules and prompts

- **Cursor rules** live inside the repo: workspace root `.cursor/rules/` (context-and-mother) and `dev/app/.cursor/rules/` (mother, project-structure). Harness rules: `dev/app/backend/harness_rules/`, `dev/app/frontend/harness_rules/`. They move with the repo.
- **Mother rules:** `dev/app/backend/harness_rules/MOTHER.md` and `dev/app/frontend/harness_rules/MOTHER.md` reference all other rules (including where to put .md files).
- **Markdown location:** New .md files must go in `dev/app/wiki/docs/` (see harness_rules/md-files-location.md).

## When making changes

After any fix, refactor, or new feature: **state whether a restart is required** for backend and/or frontend.

- **Backend** (Python/FastAPI): code and config changes need a **backend restart** (e.g. stop and run `./startup_backend.sh` or uvicorn again). With `--reload`, uvicorn auto-restarts on file save.
- **Frontend** (Vite): code changes usually hot-reload; **no restart** unless you change env, vite.config, or package.json (then restart `npm run dev`).

## After you move

1. Move the entire `development` directory to `/home/vlabs/tensor42/t42/probescout/development`.
2. Open Cursor with workspace: `/home/vlabs/tensor42/t42/probescout/development`.
3. Read this CONTEXT.md (or ask the AI to read it) so paths and structure are correct.

No Cursor prompts are stored outside this tree; everything you need is in this repo.

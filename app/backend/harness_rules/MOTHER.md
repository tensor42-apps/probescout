# Mother rule (backend)

Follow all rules in this directory. When making changes or adding features, read and apply every rule file in `dev/app/backend/harness_rules/`.

**Rules to follow:**
- `md-files-location.md` — Any .md files created must go in `dev/app/wiki/docs/` (full path: `/home/vlabs/tensor42/t42/probescout/development/dev/app/wiki/docs/`).
- `conventions.md` — Minimal md files; backend as single source of truth; no env for config.
- `backend-authority.md` — All decisions and scan logic happen in backend; API is the contract.

Cursor (and implementers) MUST follow these rules when working in `dev/app/backend/`.

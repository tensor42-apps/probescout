# Backend conventions

- Do not create excessive markdown files. Prefer in-code comments or a single `docs/` set (e.g. implementation_design.md, PRODUCT_DESIGN.md). No duplicate or redundant .md.
- Backend is the single source of truth for: scan state, action menu, guardrails, config, and all business decisions.
- Configuration: use config files (e.g. config/*.yaml). No environment variables for target, API key path, or scan parameters unless explicitly specified in implementation_design.md.
- Python-based. RestAPI (e.g. FastAPI or Flask) for all endpoints that the frontend calls.

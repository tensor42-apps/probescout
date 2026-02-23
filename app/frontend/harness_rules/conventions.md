# Frontend conventions

- Frontend is view only. It displays state and progress received from the backend API. No decisions about scan steps, actions, or guardrails.
- No business logic for nmap, LLM, or agent loop in the frontend. All such logic lives in the backend.
- Node.js-based. One screen: target input (IP or domain), one Execute button, and a status box that shows what we are doing and the output of each nmap command with stages (see implementation_design.md).
- Do not create excessive markdown files. Prefer a single README or reference to implementation_design.md.

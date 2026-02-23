# Backend authority

- All decisions (next action, goal achieved, budget, guardrails) happen in the backend. The frontend never decides scan steps or interprets nmap results.
- The backend exposes a RestAPI. The API contract (request/response shapes) is defined in implementation_design.md. Frontend only sends target (and optional params) and receives state/status/results.
- Nmap execution, LLM calls, state updates, and guardrail checks are backend-only. Frontend is a consumer of backend API.

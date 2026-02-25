# ProbeScout backend – truly agentic (goal + intents)

## How it works

- **We set the goal only.** No fixed menu of actions. The prompt is: goal + current state (target, reachability, open ports, services, OS, summary, last plan).
- **The AI proposes intents.** Reply is JSON: `intent` (host_reachability | port_scan | service_detect | os_fingerprint | wait | done), plus params when needed: for `port_scan` → `range` (any valid nmap -p spec, e.g. "1-1024", "22,80,443"); for `service_detect` → `scope` (all | common). Plus `reason`; optional `reasoning`, `plan`.
- **We validate and map to safe actions.** Guardrails parse intent + params, validate the range format (digits, commas, hyphens; ports 1–65535), and map to `action_id` (e.g. port_scan). Execution is via `get_nmap_argv(action_id, ..., port_range=...)` — no raw commands.
- **We log intent → action_id** in the scan log so you see “intent: port_scan params: {range: 1-1024} -> action_id: port_scan”.

## Why the command still uses `-oX -` (XML)

We need XML only for internal parsing (open ports, services, OS). What you see in the UI is nmap’s human-readable output (stderr). XML is never shown.

## Where the executed command is logged

- **Scan log** (section 6, and `logs/scan_<id>.log`): `[step N] command: <full command>` and `[step N] intent: ... -> action_id: ...`.
- **LLM log** (`logs/runlogs/llm_log.txt`): request/response plus `Executed command: ...` after each run.

## Config

- **goal_text** (optional): Override the goal string. If unset, we use DEFAULT_GOAL_TEXT (intent-based).
- No `goal: name` (strategy names removed). Single goal; AI decides actions via intents.

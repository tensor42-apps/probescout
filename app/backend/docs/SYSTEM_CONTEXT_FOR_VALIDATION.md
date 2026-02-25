# ProbeScout — system context for validation

**Purpose:** Self-contained summary of what we are doing: actions, action menus, command building, decision logic, and action selection. Use this to validate the design and implementation.

---

## 1. What ProbeScout is

- **Product:** AI-driven, bounded single-target reconnaissance using nmap.
- **Backend:** Owns all scan logic, state, and execution. Exposes a RestAPI (POST /api/scan, GET /api/scan/status).
- **Frontend:** View only. Sends target and receives status/stages from the API. No scan decisions.
- **Mode (v1):** Bounded agent — the AI chooses the *next action* from a fixed menu each turn; the engine validates and executes. No human-in-the-loop, no free-form commands from the AI.

---

## 2. High-level flow

1. User enters target in frontend and clicks Execute.
2. Frontend sends `POST /api/scan` with `{ "target": "hostname-or-ip" }`.
3. Backend validates target (single host or IP only), starts a scan in a background thread, returns `{ "scan_id", "status": "running" }`.
4. Backend runs the **agent loop** (see below) for that target.
5. Frontend polls `GET /api/scan/status` and displays status and per-stage output.
6. Loop runs until: goal achieved, LLM chooses `done`, or budget (max steps / max nmap runs / max time) is exceeded.

---

## 3. Actions and action_id

- **Action:** A single, allowlisted operation. Identified by a string **action_id**.
- **Allowed action_ids (v1):**  
  `host_reachability`, `wait`, `done`, `port_scan`, `service_detect`, `os_fingerprint`.
- **Meaning:**
  - **host_reachability** — Check if target is up (nmap `-sn`).
  - **wait** — Sleep (cooling); no nmap.
  - **done** — End the scan.
  - **port_scan** — TCP SYN scan (-sS) with `-p <range>`. Range is AI-proposed (e.g. "1-1024", "22,80,443"); validated format only. Requires run_nmap_sudo: true; otherwise engine raises.
  - **service_detect** — Version detection (nmap `-sV`) on open ports. Requires run_nmap_sudo: true.
  - **os_fingerprint** — OS detection (nmap `-O`).
- **Defined in code:** `dev/app/backend/action_menu.py` — intent_to_action_id, get_nmap_argv (with port_range for port_scan).

---

## 4. Action menu

- **Action menu (current menu):** The list of **action_id** values that are *valid this turn*. The AI must choose exactly one from this list.
- **Who defines it:** The **engine** (our code). The menu is derived from **current state** only.
- **Where:** `action_menu.get_current_menu(state)` in `action_menu.py`.
- **Rules:**
  - **Before any scan:** menu = `[host_reachability, wait, done]`.
  - **After host_reachability with host down (no_response):** menu = `[wait, done]` (nothing else to do).
  - **After host_reachability with host up (or any later state):** AI may propose `port_scan` with any valid `range` param (e.g. "1-1024"), or service_detect, os_fingerprint, wait, done.
- The AI proposes intents with params; we validate and map to action_id. No fixed menu; no fixed port ranges.

---

## 5. Command building

- **Who builds commands:** The **engine only**. Commands are built from a **fixed table** that maps (action_id, target, use_sudo, timeout) → argv.
- **Where:** `action_menu.get_nmap_argv(action_id, target, use_sudo, timeout_sec)` in `action_menu.py`. Returns a list of strings (e.g. `["nmap", "-sn", "--host-timeout=300", "-oX", "-", target]`) or `None` for wait/done.
- **Rules:**
  - No user or AI input is used to construct the command. Target comes from the validated API/config value only.
  - No `--script`, `-sC`, `-A`, `-iL`, `-iR`. Subprocess is always `shell=False` with a fixed argv.
  - If config says run_nmap_sudo, argv is `["sudo", "-n", "nmap", ...]`.

---

## 6. Decision logic and action selection

- **Who decides the next action:** The **LLM (AI)**. Each turn, the engine sends the current **state** (target, host reachability, open ports, services, scans run, goal progress) and the **current menu** (allowed action_ids). The LLM replies with a single JSON object: `{ "action_id": "<one of the menu>", "reason": "optional" }`.
- **Who enforces:** The **engine**. It (1) only allows action_ids that are in the current menu, (2) builds the command only via `get_nmap_argv`, (3) runs the command via subprocess (nmap_runner). It never executes a command from AI text or from an action_id not in the menu.
- **Flow each iteration:**
  1. **Budget check** — Exit if max steps, max nmap runs, or max time exceeded.
  2. **Goal check** — Exit if goal_achieved(state) (e.g. host no_response, or ports+services+OS done).
  3. **Menu** — `current_menu = get_current_menu(state)`.
  4. **Observe** — Build state text (from state) and send to LLM with the menu.
  5. **Decide** — LLM returns `{ "action_id": "..." }`.
  6. **Validate** — Parse JSON; reject if action_id missing or not in current_menu.
  7. **Act** — If action_id is `done`, exit. If `wait`, sleep (capped). Otherwise build argv with `get_nmap_argv`, run nmap, parse XML, update state.
  8. **Repeat** — Next iteration.
- **Where:** Loop in `agent.run_scan()` in `agent.py`; validation in `guardrails.validate_reply()` in `guardrails.py`; execution in `nmap_runner.run_nmap()` in `nmap_runner.py`.

---

## 7. Summary table

| Concern | Owner | Where |
|--------|--------|--------|
| What actions exist | Engine | `action_menu.py` (ALL_ACTION_IDS, get_nmap_argv) |
| Which actions are valid this turn | Engine | `action_menu.get_current_menu(state)` |
| Who chooses the next action | LLM | Replies with one action_id from the menu |
| Who validates the choice | Engine | `guardrails.validate_reply(reply, current_menu)` |
| Who builds the nmap command | Engine | `action_menu.get_nmap_argv(action_id, target, ...)` |
| Who runs the command | Engine | `nmap_runner.run_nmap()` → subprocess |
| Who updates state | Engine | `scan_state.update_from_nmap_xml(state, action_id, xml)` |

---

## 8. Safety (for validation)

- Target: Only from validated API parameter or config. Never from LLM output.
- Commands: Only from the fixed mapping in `get_nmap_argv`. No dynamic construction from AI.
- Action selection: Only accepted if `action_id` is in `get_current_menu(state)`.
- Budget: max_steps, max_nmap_runs, max_elapsed_seconds enforced before each step/nmap run.
- Wait: Sleep duration capped (e.g. 60s).
- Single target per run; no lists, ranges, or shell metacharacters in target.

---

## 9. Key files (implementation)

| File | Role |
|------|------|
| `action_menu.py` | Action IDs, get_current_menu(state), get_nmap_argv(...) — menu and command building |
| `agent.py` | run_scan() — loop: budget, goal, menu, LLM call, validate, act |
| `guardrails.py` | validate_reply(reply, current_menu), validate_target(target) |
| `nmap_runner.py` | run_nmap(target, action_id, use_sudo, timeout) — subprocess |
| `scan_state.py` | State, to_prompt_text(state), goal_achieved(state), update_from_nmap_xml(...) |
| `config_loader.py` | Load config; target, API key, limits |
| `llm_client.py` | chat(system, user) — OpenAI-compatible API |
| `app.py` | POST /api/scan, GET /api/scan/status — target validation, start scan, return status |

Full implementation spec: `implementation_design.md`. Product intent: `PRODUCT_DESIGN.md`.

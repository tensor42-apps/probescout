# AI-Agentic Nmap — Implementation design

**Use:** Implement the system from this document alone. No open decisions; every behavior and data shape is specified. Product intent is in [PRODUCT_DESIGN.md](PRODUCT_DESIGN.md); this doc is the single source of truth for implementation.

**Convention:** "MUST" / "MUST NOT" are requirements. "SHOULD" is preferred but implementer may simplify for v1 if needed.

---

## 0. Safety, anti-drifting, no hallucination, guardrails (implement first)

**Order of implementation:** Before any feature work (RestAPI, frontend, or agent loop), implement the following. This section is the first implementation step.

- **Safety**
  - Target is never taken from user input or LLM; only from backend config or from a single, validated API parameter (e.g. POST body target) that is validated (single host or IP; no lists, no ranges, no shell metacharacters). Nmap argv is built only from the fixed action_id → command table (§4); no user- or AI-supplied flags. No `--script`, `-sC`, `-A`, `-iL`, `-iR`. Run nmap via subprocess with `shell=False` and fixed argv. Sudo only as `sudo -n nmap ...` when configured.
- **Anti-drifting**
  - All behavior is defined in this document and in backend code. No behavior changes from LLM output except choosing an action from the current menu. State updates only from (1) config and (2) parsed nmap XML. No "interpretation" of AI text for targets, ports, or commands. Implementer MUST NOT add features (e.g. new nmap options or actions) without updating this doc first.
- **No hallucination (AI output not trusted as data)**
  - LLM reply is used only to select `action_id` (and optional `reason` for logs). Target, ports, and any scan parameters come from config and from state derived from nmap XML. Reject any reply that is not valid JSON with `action_id` in the current menu; do not retry; do not execute. Never use AI-suggested hostnames, IPs, or command strings for execution.
- **Guardrails (enforcement)**
  - Enforce in code: (1) action_id in current menu only; (2) budget (max_steps, max_nmap_runs, max_elapsed_seconds); (3) wait duration cap (e.g. 60s); (4) single target per run; (5) no dynamic command construction from AI. Log all rejections and budget exits. Frontend MUST NOT make scan decisions; it only displays state and progress from the backend API.

---

## 0b. Directory structure

Everything lives under **`dev/app/`**. Backend and frontend are under app.

- **`dev/app/backend/`** — All backend code. Python. RestAPI (e.g. FastAPI/Flask). Config, agent loop, nmap runner, state, guardrails. Startup: `dev/app/backend/startup_backend.sh`.
- **`dev/app/frontend/`** — All frontend code. Node.js. Single UI: target input, Execute button, status box. No scan logic. Startup: `dev/app/frontend/startup_frontend.sh`.
- **`dev/app/backend/harness_rules/`** — Mother rule + conventions and backend-authority rules. Cursor/implementers follow these when working in backend.
- **`dev/app/frontend/harness_rules/`** — Mother rule + conventions (frontend view-only). Cursor/implementers follow these when working in frontend.
- Implementation design doc: `dev/app/backend/docs/`; single source of truth. Backend is single source of truth for behavior; frontend is view only.

---

## 0c. RestAPI (backend)

- **Stack:** Python. RestAPI (e.g. FastAPI or Flask). No CLI-only; API is the primary interface for the frontend.
- **Startup:** `dev/app/backend/startup_backend.sh` — activate venv if present, start API server on port **12001** (e.g. `uvicorn app:app --reload --port 12001`). Ports: see `port_registry.yaml` / `port_table.md` under `~/tensor42/t42/launcher/`.
- **Endpoints (v1):** At least: (1) Submit scan: e.g. `POST /scan` with body `{ "target": "hostname-or-ip" }`. Target validated (single host/IP; no lists/ranges). (2) Status/results: e.g. `GET /scan/status` or `GET /scan/{id}` returning current state, step, and per-stage nmap output. Exact paths and request/response shapes to be defined when implementing; backend remains single source of truth for state and decisions.

---

## 0d. Frontend (Node.js, view only)

- **Stack:** Node.js. One screen. No business decisions; no scan logic.
- **UI:** (1) Input: target IP or domain name (single field). (2) One Execute button. (3) Status box: shows what we are doing (current step/stage), and the output of each nmap command by stage (e.g. host_reachability, then port_scan_*, service_detect, os_fingerprint). Data comes only from backend API (e.g. GET status or SSE); frontend does not parse nmap or decide actions.
- **Startup:** `dev/app/frontend/startup_frontend.sh` — `npm install` if needed, `npm run dev`. Frontend dev server on port **12000**; proxy `/api` to backend 12001 (see `vite.config.js`). Implement per this doc.

---

## 1. Scope (v1)

- **Single target** per run (one hostname or IP from config).
- **Nmap only** — no other tools. Engine runs only nmap (or wait/done).
- **Bounded agent mode only** for v1 — AI selects action from menu; engine validates and executes. No human-in-the-loop (Assistant mode) in v1.
- **First action** is always host reachability; then port scans, service detection, OS fingerprint, wait, done.

---

## 2. Config

**File:** `config/scan_config.yaml` under the backend package directory. If missing, fall back to `config/scan_profile.yaml` (same schema).

**Schema (exact keys):**

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `target` | string | yes (or target_key) | — | Single host or IP to scan. |
| `target_key` | int or string | no | — | If set, resolve target from `config/targets.yaml` (index or key). Ignored if `target` is set. |
| `llm.type` | string | no | `"remote"` | `"remote"` = OpenAI-compatible API. |
| `llm.openai_api_key_file` | string | no | `"config/openai.key.ignore"` | Path relative to backend dir; file contains API key (first non-empty line, or KEY=value). |
| `run_nmap_sudo` | bool | no | true | If true, run nmap as `sudo -n nmap ...`. |
| `nmap_execution` | bool | no | true | If false, do not run nmap (dry run: loop and LLM only). |
| `cooling` | bool | no | true | If true, when action is `wait`, actually sleep. |
| `cooling_seconds` | int | no | 4 | Seconds to sleep when action is `wait`; cap at 60. |
| `dry_run` | bool | no | false | Same as nmap_execution=false. |
| `max_steps` | int | no | 30 | Hard cap on loop iterations. |
| `max_nmap_runs` | int | no | 25 | Hard cap on number of nmap invocations. |
| `max_elapsed_seconds` | int | no | 3600 | Hard cap on wall-clock time (seconds). |

**Resolved target:** Must be a single string (hostname or IP). Engine MUST use only this value for every nmap call; never use target from AI or from any other source.

**API key:** Read from file path resolved relative to backend root. File encoding UTF-8 (BOM allowed). First non-empty line: if it contains `=`, use the part after `=`; otherwise use the whole line. Strip whitespace. No format validation (sk- or sk-proj- both allowed).

---

## 3. State model

**Owner:** Engine only. Updated only after each Act (nmap result or wait/done).

**Data structure (in-code):**

- `target: str` — From config; never from AI.
- `host_reachability: Literal["unknown", "up", "no_response"]` — Set after action `host_reachability`. `up` if nmap -sn reported host up; `no_response` otherwise. No "filtered" in v1.
- `host_addr: Optional[str]` — IPv4 address from nmap output if present.
- `hostname: Optional[str]` — Hostname from nmap if present.
- `open_ports: List[Tuple[int, str]]` — (port, protocol). Merged from all port scans; protocol default "tcp".
- `services: List[Tuple[int, str, Optional[str], Optional[str]]]` — (port, protocol, service_name, version). From service_detect run.
- `os_fingerprint_done: bool` — True if action `os_fingerprint` was run (regardless of result).
- `scans_run: List[str]` — Ordered list of action_id that were executed (e.g. `["host_reachability", "port_scan_1_100"]`).
- `nmap_run_count: int` — Number of nmap invocations so far (for budget).

**Initial state:** target = config target; host_reachability = "unknown"; host_addr, hostname = None; open_ports, services = []; os_fingerprint_done = False; scans_run = []; nmap_run_count = 0.

**State → prompt text (exact format for LLM):**

Emit a single text block with lines:

- `Target: <target>`
- `Host reachability: <unknown|up|no_response>`
- If host_addr: `Host address: <host_addr>`
- If hostname: `Hostname: <hostname>`
- `Open ports: <comma-separated port/proto or "none">`
- If services: for each, `  <port>/<proto>: <service> <version>`
- `Goal progress: host_known=<true|false> ports_known=<true|false> services_known=<true|false> os_known=<true|false>`
- `Scans run: <comma-separated action_ids>`

Definitions: host_known = (host_reachability != "unknown"). ports_known = (len(open_ports) > 0 or any port_scan action in scans_run). services_known = (len(services) > 0 or "service_detect" in scans_run). os_known = os_fingerprint_done.

**goal_achieved(state) → bool:**

- If host_reachability == "no_response": return True (nothing more to do).
- If host_reachability != "up": return False.
- Return (ports_known and services_known and os_known). Where ports_known = len(open_ports) > 0 or "port_scan_1_100" in scans_run or "port_scan_1_1000" in scans_run or "port_scan_1_65535" in scans_run; services_known = "service_detect" in scans_run; os_known = os_fingerprint_done.

---

## 4. Action menu and engine mapping

**Allowed action_id set (v1):** `host_reachability`, `wait`, `done`, `port_scan_1_100`, `port_scan_1_1000`, `port_scan_1_65535`, `service_detect`, `os_fingerprint`.

**Current menu (which actions are valid this turn):**

- **Before any scan:** menu = [host_reachability, wait, done].
- **After host_reachability with host_reachability == "up":** menu = [port_scan_1_100, port_scan_1_1000, port_scan_1_65535, service_detect, os_fingerprint, wait, done]. Optionally omit service_detect until at least one port_scan has run; for v1 keep all in menu once host is up.
- **After host_reachability with host_reachability == "no_response":** menu = [wait, done] only.
- **Any other state:** menu = full set minus host_reachability (we already ran it): [port_scan_1_100, port_scan_1_1000, port_scan_1_65535, service_detect, os_fingerprint, wait, done].

**Engine mapping (action_id → execution):**

| action_id | Type | Execution |
|-----------|------|-----------|
| host_reachability | nmap | `nmap -sn --host-timeout <timeout_sec> -oX - <target>`. timeout_sec from config or 300. No -p. |
| wait | wait | Sleep min(reply reason or config cooling_seconds, 60). Append to scans_run. Do not increment nmap_run_count. |
| done | done | Exit loop; do not run nmap. |
| port_scan_1_100 | nmap | `nmap -sS -p 1-100 -T3 --host-timeout 300 -oX - <target>`. If run_nmap_sudo: use sudo -n. |
| port_scan_1_1000 | nmap | `nmap -sS -p 1-1000 -T3 --host-timeout 300 -oX - <target>`. |
| port_scan_1_65535 | nmap | `nmap -sS -p 1-65535 -T3 --host-timeout 300 -oX - <target>`. |
| service_detect | nmap | `nmap -sS -sV -p 1-65535 -T3 --host-timeout 300 -oX - <target>`. (Fixed range for v1; can later use state.open_ports.) |
| os_fingerprint | nmap | `nmap -O --host-timeout 300 -oX - <target>`. No -p. |

**Target:** Always the resolved config target. Never from AI.

**Nmap output:** Always `-oX -` (XML to stdout). Engine parses XML to update state (host status, ports, services, OS). Use namespace-agnostic parsing for port/state/service elements.

---

## 5. AI response format

**Only accepted format:** A single JSON object with exactly the following rules.

**Allowed fields:** `action_id` (required), `reason` (optional string). Any other field MUST be ignored for execution (do not reject the reply for extra fields; strip to action_id and reason only).

**Schema:**

- `action_id`: string. MUST be one of the current menu action IDs (case-sensitive). If missing or not in menu → reject (do not execute).
- `reason`: optional string. Used for logging/audit only; not used for execution.

**Reject (do not execute, do not update state):**

- Reply body is empty or whitespace-only.
- After stripping markdown (see below), body is not valid JSON (json.loads raises).
- JSON is valid but `action_id` key is missing.
- `action_id` is not in the current allowed menu for this turn.

**On reject:** Log the reply and rejection reason to stderr. Do not retry the LLM in v1. Advance to next iteration (increment step count; do not append to scans_run). If max_steps exceeded, exit loop.

**Parsing steps (in order):**

1. Take the raw LLM reply string. Strip leading and trailing whitespace.
2. If reply contains newline, take only the first line (before first \n).
3. Remove a single markdown code fence if present: if line starts with ``` (optional json) and ends with ```, replace with the substring between them and strip.
4. `data = json.loads(line)`.
5. `action_id = data.get("action_id")`. If action_id is None or not a string, reject.
6. If action_id not in current_menu: reject.
7. Otherwise accept; optional reason = data.get("reason") (string or None).

**Prompt to LLM (exact structure):**

System message (concatenate in order):

1. "Goal: " + goal text (from config or fixed: "Find open ports, identify services and versions, and perform OS fingerprint on the target.").
2. "Guardrails: Respond with only one JSON object. Required field: \"action_id\" (must be exactly one of the allowed values below). Optional: \"reason\". No other fields. No markdown, no explanation outside JSON."
3. "Allowed action_id this turn: " + comma-separated list of current menu IDs.

User message (each turn):

1. State block (from state → prompt text above).
2. "Choose the next action. Reply with only a JSON object with \"action_id\" and optionally \"reason\"."

---

## 6. Guardrails (enforcement)

All in engine code. No execution from AI output except via action_id → mapping.

- **Scope:** Target is always from config. Never read target from LLM reply. Ignore any "target" in JSON.
- **Action menu:** Before executing, MUST check action_id in current_menu. If not in list, reject (no execution).
- **Command construction:** Build nmap argv only from the fixed table in §4. No user/AI-supplied flags. No --script, -sC, -A, -iL, -iR ever.
- **Budget:** Before each iteration: if step_count >= max_steps, exit loop. Before each nmap run: if nmap_run_count >= max_nmap_runs, skip nmap and exit or skip (do not run nmap). At start of each iteration: if (now - start_time) > max_elapsed_seconds, exit loop.
- **Sudo:** If run_nmap_sudo: run subprocess with argv = ["sudo", "-n", nmap_path, ...nmap_args..., target]. Never shell=True. Never pass a single string command.
- **Wait cap:** When action is wait, sleep duration = min(parsed_seconds_from_reason_or_default, 60). Default from config cooling_seconds (e.g. 4).

---

## 7. Loop (control flow)

**Pre-loop:**

1. Load config from config/scan_config.yaml (or scan_profile.yaml). Resolve target. Validate: target non-empty.
2. If nmap_execution is true: check nmap on PATH; if run_nmap_sudo, run `sudo -n true` and fail fast if it fails.
3. Initialize state (see §3). step_count = 0. start_time = now. nmap_run_count = 0 (also in state).

**Each iteration:**

1. step_count += 1.
2. **Budget check:** If step_count > max_steps, exit loop. If (now - start_time) > max_elapsed_seconds, exit loop.
3. **Goal check:** If goal_achieved(state), exit loop.
4. **Current menu:** Compute allowed action_id list from state (§4).
5. **Observe:** Build state prompt text (§3) and user message (§5).
6. **Decide:** Call LLM (system + user). Get reply string. On LLM failure (network, API error): log, treat as reject; go to step 10 (no execution).
7. **Parse:** Apply parsing steps (§5). If reject: log, go to step 10.
8. **Act:** If action_id == "done", exit loop. If action_id == "wait", sleep (cap 60s), append "wait" to scans_run, go to step 10. Else: check action_id in current menu again; if not in menu, reject and go to step 10. Check nmap_run_count < max_nmap_runs; if not, exit loop. Build nmap argv from §4; run nmap (or dry-run: do not run, but append action_id to scans_run and do not update host/ports). On nmap run: nmap_run_count += 1; parse XML; update state (host_reachability, open_ports, services, os_fingerprint_done, etc.). Append action_id to scans_run.
9. **Evaluate:** State already updated in Act. No separate step.
10. **Repeat:** Go to step 1 (next iteration).

**Post-loop:** Output final state (see §9). Return state and scan history to caller (CLI or API).

---

## 8. Execution (nmap runner)

**Interface:** `run_nmap(target: str, action_id: str, use_sudo: bool, timeout_sec: int = 300) -> (raw_command: str, xml_output: str, return_code: int)`.

**Behavior:** Build argv from the action_id mapping (§4). Target is always the passed-in target (from config). Append `--host-timeout`, `timeout_sec`, `-oX`, `-`, and target. Run via subprocess.run(..., shell=False, capture_output=True, text=True, timeout=timeout_sec+60). Return the command string (for logging), stdout (XML), and returncode. If timeout or exception, return (raw_command, "", non_zero or 1).

**Parsing XML:** From nmap stdout, extract: host status (up/down), address, hostname; for each port: portid, protocol, state (open/filtered/closed), service name and version. Merge into state: update host_reachability for host_reachability action; merge open_ports and services from port_scan and service_detect; set os_fingerprint_done for os_fingerprint action. Use namespace-agnostic tag names (e.g. local name "port", "state", "service").

---

## 9. Output and CLI

**Stderr (progress):** Print per iteration: step number, "Reply: <reply>", "Run: <action_id> [or command summary]", "Done: <summary>". No need to print full XML.

**Stdout (final results):** After loop, print a summary block: list of scans_run; open ports per host; services; OS if known. Format: human-readable lines. Optionally also print a JSON blob of final state (target, host_reachability, open_ports, services, os_fingerprint_done, scans_run) for machine consumption.

**Exit code:** 0 on normal exit (done or goal_achieved or budget); 1 on config error, pre-flight failure (nmap/sudo), or unhandled exception.

**CLI entrypoint:** Single command (e.g. `python -m backend.cli` or `./run_nmap.sh`). No positional args for target; target from config. No env vars required except for API key path if not in config.

---

## 10. File and module layout

**Package root:** Backend package directory (e.g. `backend/` or project root where backend lives).

**Modules:**

- `config_loader.py` — Load scan_config.yaml (or scan_profile.yaml). Expose get_scan_target(), get_run_nmap_sudo(), get_nmap_execution(), get_cooling(), get_cooling_seconds(), get_max_steps(), get_max_nmap_runs(), get_max_elapsed_seconds(), get_openai_api_key() (from key file path in config).
- `scan_state.py` — State dataclass or class; to_prompt_text(); goal_achieved(state); update_from_nmap_xml(state, action_id, xml_str).
- `action_menu.py` — ALL_ACTION_IDS; get_current_menu(state) -> list of action_id; get_nmap_argv(action_id, target, use_sudo, timeout_sec) -> list of str (argv for nmap or None for wait/done).
- `guardrails.py` — validate_reply(reply: str, current_menu: list) -> (action_id, reason) or None (reject). Apply parsing steps from §5; return (action_id, reason) if valid, else None.
- `nmap_runner.py` — run_nmap(target, action_id, use_sudo, timeout_sec); return (raw_command, xml_stdout, returncode). Parse XML internally or in scan_state. Never add --script, -sC, -A, -iL, -iR.
- `llm_client.py` — chat(system: str, user: str) -> str. Build request from system and user; call OpenAI-compatible API; return response content (first choice message content or equivalent). API key from config_loader.
- `agent.py` — run_scan(): load config, init state, pre-flight, loop as in §7, return (state, scans_run or equivalent). No print to stdout inside loop except stderr progress.
- `cli.py` — main(): run_scan(); print_result(state) to stdout; handle exceptions and exit code.

**Config file path:** Resolve relative to backend package directory: `CONFIG_DIR = Path(__file__).resolve().parent / "config"`, then `CONFIG_DIR / "scan_config.yaml"`.

---

## 11. Error handling

- **Config missing or invalid:** Raise or log; exit with code 1. Do not start loop.
- **Target unresolved:** Raise or log; exit with code 1.
- **API key file missing or empty:** Raise; exit with code 1.
- **Nmap not on PATH:** Raise before loop; exit with code 1.
- **Sudo -n failed (password required):** Raise before loop; exit with code 1.
- **LLM call failed (network, 4xx/5xx):** Log; treat reply as reject; do not execute; continue to next iteration (or exit if step_count already at max_steps).
- **Reply parse reject:** Log; do not execute; continue to next iteration.
- **Nmap run timeout or non-zero exit:** Update state from XML if any; if host_reachability action and no host in output, set host_reachability = "no_response". Append action_id to scans_run. Continue loop.

---

## 12. Summary checklist for implementer

- [ ] **First:** Section 0 — Safety, anti-drifting, no hallucination, guardrails (implement before any feature work).
- [ ] Directory structure: dev/app/backend, dev/app/frontend; harness_rules in each; startup_backend.sh, startup_frontend.sh.
- [ ] RestAPI: Python backend with POST/GET scan endpoints; target validation; state and nmap output exposed to frontend.
- [ ] Frontend: Node.js; target input, Execute button, status box (stages + nmap output from API only).
- [ ] Config: scan_config.yaml with target, llm.openai_api_key_file, run_nmap_sudo, max_steps, max_nmap_runs, max_elapsed_seconds, cooling_seconds.
- [ ] State: target, host_reachability, host_addr, hostname, open_ports, services, os_fingerprint_done, scans_run, nmap_run_count. Initial: unknown, empty lists, 0.
- [ ] Menu: before host_reachability → [host_reachability, wait, done]. After no_response → [wait, done]. After up → full list without host_reachability.
- [ ] Mapping: each action_id to nmap argv or wait/done; target always from config; -oX -; no scripts.
- [ ] AI: JSON only; action_id required, reason optional; strip first line and markdown; reject if invalid or not in menu; no retry.
- [ ] Loop: pre-flight → loop (budget, goal, menu, observe, LLM, parse, act, update state) until done or goal or budget.
- [ ] Guardrails: scope (target config), menu check, budget (steps, nmap runs, elapsed), sudo shell=False, wait cap 60.
- [ ] Output: stderr progress; stdout final summary; exit 0/1.
- [ ] Modules: config_loader, scan_state, action_menu, guardrails, nmap_runner, llm_client, agent, cli.

Implement from this document; no design decisions left open for v1.

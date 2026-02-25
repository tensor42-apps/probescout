# Audit: Wait intent and goal alignment

## Why we were “waiting”

- **Original idea:** “Wait” was implemented so the **LLM could request a pause** between scans. When the LLM replied with `intent: "wait"`, the backend slept for `cooling_seconds` (config). So cooling was **LLM-driven**: the model decided when to wait.
- **Config:** `scan_config.yaml` has `cooling: true` and `cooling_seconds: 4`. Those values were only used when the LLM chose the “wait” intent; there was **no automatic** sleep after nmap runs.

## Where “wait” appears (legacy)

| Location | What |
|----------|------|
| **goal.py** | `_INTENT_SCHEMA` lists `wait` as an allowed intent in the reply format. So the **goal text** we send to the LLM says it may reply with `host_reachability, port_scan, service_detect, os_fingerprint, wait, done`. |
| **action_menu.py** | `ALLOWED_INTENTS` includes `"wait"`; mapping `intent "wait"` → action_id `"wait"`. |
| **agent.py** | Branch `if action_id == "wait"`: parse seconds from reason, `time.sleep(wait_sec)` when `cooling` is true, append to `scans_run` and `stage_outputs`, then continue loop. Also `consecutive_waits` cap (reject wait after 2 in a row). |
| **scan_state.py** | `to_prompt_text()`: when no open ports, hint says “use \"done\" or \"wait\" (or run another port_scan)”. And when `consecutive_waits >= 2`, hint “prefer 'done' or a scan action (no more wait)”. |

So the LLM was **allowed and even prompted** to use “wait”, but **goal.md never mentions wait or cooling**. Goals in goal.md are only: simple_recon, well_known_tcp, full_stealth_tcp (and future common_ports, etc.) with descriptions and `achieved_when`. “Wait” is an **operational** mechanism (cooling), not part of the goal semantics.

## Strict alignment with goal.md

- **Single source of truth:** goal.md defines goal **names**, **descriptions**, and **achieved_when**. Implementation lives in goal.py (GOALS, goal text, `goal_achieved`).
- **What we send to the LLM:** We send **goal text** (from goal.py, keyed by goal_id from the API) plus **state** (target, reachability, open ports, scans run, etc.). The LLM replies with a single **intent** (+ params, reason, etc.).
- **Intents that match goal.md:** For the described goals, the only **goal-level** actions are: check host, run port scan, run service detection, run OS fingerprint, and **done**. So the intent set should be: `host_reachability`, `port_scan`, `service_detect`, `os_fingerprint`, `done`. No “wait” in the goal list.
- **Cooling:** Cooling between nmap runs is a **backend policy** (config: `cooling`, `cooling_seconds`), not a goal. So it should be implemented as **automatic** sleep after each nmap run when `cooling` is true, instead of an LLM intent.

## Changes made (post-audit)

1. **Remove “wait” from intents:** Removed from `_INTENT_SCHEMA` in goal.py and from `ALLOWED_INTENTS` (and intent→action mapping) in action_menu.py. Guardrails and agent no longer accept or handle `intent: "wait"`.
2. **Automatic cooling:** After each successful nmap run (in agent.py), when `cooling` is true and `cooling_seconds > 0`, the backend does `time.sleep(cooling_seconds)` before the next LLM turn. No LLM decision involved.
3. **Prompt hints:** Removed “wait” from to_prompt_text (no “use done or wait”, no `consecutive_waits` hint). State hints only mention “done” or “run another port_scan” where relevant.
4. **goal.md:** Documented that cooling between nmap runs is a backend policy (config), not an LLM intent.

Result: **Goals and intents are strictly aligned with goal.md;** cooling is a backend policy only.

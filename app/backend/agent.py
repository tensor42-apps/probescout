"""
Agent loop: load config, pre-flight, run Observe→Decide→Act loop. Implementation design §7, §10.
Timestamps and log file are backend (business) logic only.
"""
import sys
import time
from datetime import datetime
from typing import Callable, List, Optional, Tuple

import config_loader
from scan_state import ScanState, goal_achieved, to_prompt_text, update_from_nmap_xml
from action_menu import get_current_menu, get_nmap_argv
from guardrails import validate_reply
from nmap_runner import run_nmap, check_nmap_on_path, check_sudo_nopasswd
from llm_client import chat

DEFAULT_TIMEOUT = 300


def _parse_wait_seconds(reason: Optional[str], default_sec: int) -> int:
    if not reason:
        return min(default_sec, 60)
    s = reason.strip()
    for word in s.split():
        word = word.rstrip("s")
        try:
            n = int(word)
            return max(0, min(n, 60))
        except ValueError:
            continue
    return min(default_sec, 60)


def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_scan(
    target_override: Optional[str] = None,
    progress_callback: Optional[Callable[..., None]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> Tuple[ScanState, List[str], List[Tuple[str, str, float]]]:
    """
    Load config, resolve target (or use target_override if provided), pre-flight, run loop.
    Returns (state, scans_run, stage_outputs) where stage_outputs is [(action_id, output_text, started_ts), ...].
    progress_callback(step, state, last_action_id, stage_outputs, log_message=None).
    log_callback(line) is called for each log line (backend writes to log file and buffers for API).
    """
    print("[ProbeScout] agent.run_scan() entered", file=sys.stderr, flush=True)
    config_loader._load_config()
    print("[ProbeScout] agent: config loaded", file=sys.stderr, flush=True)
    target = target_override if target_override else config_loader.get_scan_target()
    if not target or not str(target).strip():
        raise ValueError("Target is required and must be non-empty")
    target = str(target).strip()

    # API key is already validated by the API layer before starting the scan thread; skip here to avoid blocking the thread on a second network call.

    run_sudo = config_loader.get_run_nmap_sudo()
    nmap_execution = config_loader.get_nmap_execution()
    cooling = config_loader.get_cooling()
    cooling_seconds = config_loader.get_cooling_seconds()
    max_steps = config_loader.get_max_steps()
    max_nmap_runs = config_loader.get_max_nmap_runs()
    max_elapsed_seconds = config_loader.get_max_elapsed_seconds()
    goal_text = config_loader.get_goal_text()

    if nmap_execution:
        if not check_nmap_on_path():
            raise RuntimeError("nmap not found on PATH")
        if run_sudo and not check_sudo_nopasswd():
            raise RuntimeError("sudo -n failed (password required)")

    state = ScanState.initial(target)
    step_count = 0
    start_time = time.time()
    stage_outputs: List[Tuple[str, str, float]] = []
    last_action_id = ""
    print("[ProbeScout] agent: state ready, entering loop", file=sys.stderr, flush=True)

    def _log(line: str) -> None:
        if log_callback:
            log_callback(line)

    system_prefix = (
        "Goal: " + goal_text + "\n"
        "Guardrails: Respond with only one JSON object. Required field: \"action_id\" (must be exactly one of the allowed values below). Optional: \"reason\". No other fields. No markdown, no explanation outside JSON.\n"
    )

    while True:
        step_count += 1
        if step_count > max_steps:
            break
        if (time.time() - start_time) > max_elapsed_seconds:
            break
        if goal_achieved(state):
            break

        step_start_time = time.time()
        menu = get_current_menu(state)
        system_msg = system_prefix + "Allowed action_id this turn: " + ", ".join(menu)
        state_block = to_prompt_text(state)
        user_msg = state_block + "\nChoose the next action. Reply with only a JSON object with \"action_id\" and optionally \"reason\"."

        reply = ""
        print(f"[ProbeScout] agent: step {step_count} calling progress_callback then LLM", file=sys.stderr, flush=True)
        if progress_callback:
            progress_callback(step_count, state, last_action_id, stage_outputs, "Calling LLM…")
        try:
            reply = chat(system_msg, user_msg)
            print(f"[ProbeScout] agent: step {step_count} LLM returned", file=sys.stderr, flush=True)
        except Exception as e:
            err_msg = f"LLM error: {e}"
            print(f"[step {step_count}] {err_msg}", file=sys.stderr)
            if progress_callback:
                progress_callback(step_count, state, last_action_id, stage_outputs, err_msg)
            continue

        parsed = validate_reply(reply, menu)
        if parsed is None:
            reject_msg = f"Rejected: invalid or not in menu (reply: {reply[:80]}…)" if len(reply) > 80 else f"Rejected: invalid or not in menu (reply: {reply!r})"
            print(f"[step {step_count}] {reject_msg}", file=sys.stderr)
            if progress_callback:
                progress_callback(step_count, state, last_action_id, stage_outputs, reject_msg)
            continue

        action_id, reason = parsed
        last_action_id = action_id

        if action_id == "done":
            _log(f"[{_ts()}] [step {step_count}] done\n")
            if progress_callback:
                progress_callback(step_count, state, action_id, stage_outputs, "Done.")
            break

        if action_id == "wait":
            _log(f"[{_ts()}] [step {step_count}] wait started\n")
            wait_sec = _parse_wait_seconds(reason, cooling_seconds)
            if cooling and wait_sec > 0:
                time.sleep(wait_sec)
            state.scans_run.append("wait")
            stage_outputs.append(("wait", f"Waited {wait_sec}s", step_start_time))
            _log(f"[{_ts()}] [step {step_count}] wait done (Waited {wait_sec}s)\n---\n")
            if progress_callback:
                progress_callback(step_count, state, action_id, stage_outputs, f"Waited {wait_sec}s")
            continue

        if action_id not in menu:
            if progress_callback:
                progress_callback(step_count, state, last_action_id, stage_outputs, "Rejected: not in menu")
            continue
        if state.nmap_run_count >= max_nmap_runs:
            break
        if get_nmap_argv(action_id, target, run_sudo, DEFAULT_TIMEOUT) is None:
            if progress_callback:
                progress_callback(step_count, state, action_id, stage_outputs, "No nmap argv")
            continue

        _log(f"[{_ts()}] [step {step_count}] {action_id} started\n")
        if nmap_execution:
            raw_cmd, xml_out, returncode = run_nmap(target, action_id, run_sudo, DEFAULT_TIMEOUT)
            state.nmap_run_count += 1
            output_summary = raw_cmd
            update_from_nmap_xml(state, action_id, xml_out or "")
            if xml_out:
                output_summary = xml_out[:2000] + ("..." if len(xml_out) > 2000 else "")
            state.scans_run.append(action_id)
            stage_outputs.append((action_id, output_summary, step_start_time))
            out_len = len(output_summary)
            _log(f"[{_ts()}] [step {step_count}] {action_id} done ({out_len} chars) — see Output panel for full output\n")
        else:
            state.scans_run.append(action_id)
            stage_outputs.append((action_id, "(dry run)", step_start_time))
            _log(f"[{_ts()}] [step {step_count}] {action_id} done (dry run)\n---\n")

        if progress_callback:
            progress_callback(step_count, state, action_id, stage_outputs, f"Ran: {action_id}")

    return (state, state.scans_run, stage_outputs)

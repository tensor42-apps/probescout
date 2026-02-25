"""
Agent loop: load config, pre-flight, run Observe→Decide→Act loop. Implementation design §7, §10.
Timestamps and log file are backend (business) logic only.
"""
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import config_loader
from goal import goal_achieved
from scan_state import ScanState, format_nmap_xml_summary, to_prompt_text, update_from_nmap_xml
from action_menu import command_for_display, get_action_label, get_nmap_argv
from guardrails import validate_intent
from nmap_runner import run_nmap, check_nmap_on_path, check_sudo_nopasswd
from llm_client import chat

DEFAULT_TIMEOUT = 300




def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_scan(
    target_override: Optional[str] = None,
    progress_callback: Optional[Callable[..., None]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    output_stream_callback: Optional[Callable[[str], None]] = None,
    llm_log_path: Optional[Path] = None,
    goal_text_override: Optional[str] = None,
    goal_id: Optional[str] = None,
) -> Tuple[ScanState, List[str], List[Tuple[str, str, float]]]:
    """
    Load config, resolve target (or use target_override if provided), pre-flight, run loop.
    Returns (state, scans_run, stage_outputs) where stage_outputs is [(action_id, output_text, started_ts), ...].
    progress_callback(step, state, last_action_id, stage_outputs, log_message=None).
    log_callback(line) is called for each log line (backend writes to log file and buffers for API).
    output_stream_callback(line) is called with nmap stderr (-vv) lines while nmap is running.
    llm_log_path: if set, each LLM request/response is appended to this file for debugging.
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
    goal_text = goal_text_override if goal_text_override else config_loader.get_goal_text()

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
    consecutive_rejections = 0
    max_consecutive_rejections = 5  # stop early if LLM keeps proposing invalid intents
    print("[ProbeScout] agent: state ready, entering loop", file=sys.stderr, flush=True)

    def _log(line: str) -> None:
        if log_callback:
            log_callback(line)

    role_instruction = (
        "You are a seasoned pentester. You are expert in capture-the-flag challenges. "
        "You know network security well. You are expert in recon and port scanning. "
        "You are also expert in nmap and know all the commands. Stick only to nmap. No other help is required.\n\n"
    )
    system_msg = role_instruction + "Goal: " + goal_text
    last_plan: Optional[str] = None

    while True:
        step_count += 1
        if step_count > max_steps:
            break
        if (time.time() - start_time) > max_elapsed_seconds:
            break
        if goal_achieved(state, goal_id):
            break

        step_start_time = time.time()
        state_block = to_prompt_text(state, last_plan=last_plan)
        user_msg = state_block + "\nPropose your next step (JSON: intent, params as needed, reason; optional reasoning, plan)."

        reply = ""
        print(f"[ProbeScout] agent: step {step_count} calling progress_callback then LLM", file=sys.stderr, flush=True)
        if progress_callback:
            progress_callback(step_count, state, last_action_id, stage_outputs, "Calling LLM…")
        try:
            reply = chat(system_msg, user_msg, log_path=llm_log_path)
            print(f"[ProbeScout] agent: step {step_count} LLM returned", file=sys.stderr, flush=True)
        except Exception as e:
            err_msg = f"LLM error: {e}"
            print(f"[step {step_count}] {err_msg}", file=sys.stderr)
            if progress_callback:
                progress_callback(step_count, state, last_action_id, stage_outputs, err_msg)
            continue

        parsed = validate_intent(reply, state, goal_id)
        if parsed is None:
            consecutive_rejections += 1
            reject_msg = f"Rejected: invalid intent or params (reply: {reply[:80]}…)" if len(reply) > 80 else f"Rejected: invalid intent (reply: {reply!r})"
            print(f"[step {step_count}] {reject_msg}", file=sys.stderr)
            if progress_callback:
                progress_callback(step_count, state, last_action_id, stage_outputs, reject_msg)
            if consecutive_rejections >= max_consecutive_rejections:
                print(f"[ProbeScout] agent: {consecutive_rejections} consecutive rejections; stopping to avoid burning all steps", file=sys.stderr)
                _log(f"[{_ts()}] Stopped after {consecutive_rejections} consecutive invalid intents (max {max_consecutive_rejections}).\n")
                break
            continue

        consecutive_rejections = 0
        action_id, reason, reasoning, plan, intent, params = parsed
        last_action_id = action_id
        if plan:
            last_plan = plan
        intent_log_line = f"Intent: {intent}" + (f" params: {params}" if params else "") + f" -> action_id: {action_id}\n"
        _log(f"[{_ts()}] [step {step_count}] {intent_log_line.strip()}\n")
        if llm_log_path:
            try:
                with open(llm_log_path, "a", encoding="utf-8") as f:
                    f.write(intent_log_line + "\n")
            except OSError:
                pass

        if action_id == "done":
            done_msg = f"Done. Reason: {reason.strip()}" if reason and reason.strip() else "Done."
            if reasoning and reasoning.strip():
                _log(f"[{_ts()}] [step {step_count}] reasoning: {reasoning.strip()}\n")
            _log(f"[{_ts()}] [step {step_count}] done\n")
            if progress_callback:
                progress_callback(step_count, state, action_id, stage_outputs, done_msg)
            break

        if state.nmap_run_count >= max_nmap_runs:
            break
        port_range_arg = (params.get("range") or params.get("port_range")) if action_id == "port_scan" else None
        # Full 1-65535 scan needs longer host-timeout or nmap times out before writing port results (XML has no <ports>). Goal: 60 min.
        timeout_sec = 3600 if (action_id == "port_scan" and port_range_arg == "1-65535") else DEFAULT_TIMEOUT
        argv = get_nmap_argv(action_id, target, run_sudo, timeout_sec, open_ports=state.open_ports, port_range=port_range_arg)
        if argv is None:
            if progress_callback:
                progress_callback(step_count, state, action_id, stage_outputs, "No nmap argv")
            continue

        display_cmd = command_for_display(argv)
        _log(f"[{_ts()}] [step {step_count}] {action_id} started\n")
        _log(f"[{_ts()}] [step {step_count}] command: {display_cmd}\n")
        if llm_log_path:
            try:
                with open(llm_log_path, "a", encoding="utf-8") as f:
                    f.write(f"Executed command: {display_cmd}\n\n")
            except OSError:
                pass
        if nmap_execution:
            if progress_callback:
                run_msg = f"Running: {action_id}…"
                if reason and reason.strip():
                    run_msg += f" Reason: {reason.strip()}"
                if reasoning and reasoning.strip():
                    run_msg += f" Reasoning: {reasoning.strip()}"
                if plan and plan.strip():
                    run_msg += f" Plan: {plan.strip()}"
                progress_callback(
                    step_count,
                    state,
                    action_id,
                    stage_outputs,
                    run_msg,
                    current_command=display_cmd,
                )
            if reasoning and reasoning.strip():
                _log(f"[{_ts()}] [step {step_count}] reasoning: {reasoning.strip()}\n")
            if plan and plan.strip():
                _log(f"[{_ts()}] [step {step_count}] plan: {plan.strip()}\n")
            _, xml_out, returncode, raw_nmap_output = run_nmap(
                target,
                action_id,
                run_sudo,
                timeout_sec,
                open_ports=state.open_ports,
                port_range=port_range_arg if action_id == "port_scan" else None,
                output_stream_callback=output_stream_callback,
            )
            # Diagnostic: write what we got from nmap and state after parse
            if llm_log_path:
                try:
                    debug_path = Path(llm_log_path).parent / "nmap_xml_debug.txt"
                    with open(debug_path, "w", encoding="utf-8") as f:
                        f.write(f"action_id={action_id} returncode={returncode} len(xml_out)={len(xml_out or '')}\n")
                        f.write(f"xml_out preview: {repr((xml_out or '')[:600])}\n")
                except OSError:
                    pass
            state.nmap_run_count += 1
            update_from_nmap_xml(
                state,
                action_id,
                xml_out or "",
                debug_path=str(Path(llm_log_path).parent / "nmap_xml_debug.txt") if (llm_log_path and action_id == "port_scan") else None,
            )
            if llm_log_path and action_id == "port_scan":
                try:
                    debug_path = Path(llm_log_path).parent / "nmap_xml_debug.txt"
                    with open(debug_path, "a", encoding="utf-8") as f:
                        f.write(f"after update_from_nmap_xml: len(state.open_ports)={len(state.open_ports)} open_ports={state.open_ports}\n")
                except OSError:
                    pass
            # Persist every nmap XML under backend/logs/ as target_<timestamp>.xml and log name in llm_log.txt
            if llm_log_path and (xml_out or "").strip():
                try:
                    logs_dir = Path(llm_log_path).parent.parent  # runlogs -> logs
                    logs_dir.mkdir(parents=True, exist_ok=True)
                    safe_target = re.sub(r"[^\w\-.]", "_", target).strip("_") or "target"
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    xml_filename = f"{safe_target}_{ts}.xml"
                    xml_path = logs_dir / xml_filename
                    with open(xml_path, "w", encoding="utf-8") as f:
                        f.write(xml_out or "")
                    rel = f"logs/{xml_filename}"
                    with open(llm_log_path, "a", encoding="utf-8") as f:
                        f.write(f"Nmap XML: {rel}\n\n")
                except OSError:
                    pass
            # Display raw nmap output (human-readable); fallback to summary if no raw output (e.g. no callback).
            stage_display = (raw_nmap_output or "").strip() or format_nmap_xml_summary(xml_out or "", action_id)
            state.scans_run.append(action_id)
            stage_outputs.append((action_id, stage_display, step_start_time))
            out_len = len(stage_display)
            _log(f"[{_ts()}] [step {step_count}] {action_id} done ({out_len} chars) — see Output panel for full output\n")
        else:
            state.scans_run.append(action_id)
            stage_outputs.append((action_id, "(dry run)", step_start_time))
            _log(f"[{_ts()}] [step {step_count}] {action_id} done (dry run)\n---\n")

        # Cooling between nmap runs is backend policy (config), not an LLM intent.
        if nmap_execution and cooling and cooling_seconds > 0:
            time.sleep(cooling_seconds)

        if progress_callback:
            progress_callback(step_count, state, action_id, stage_outputs, f"Ran: {action_id}")

    _log(f"[{_ts()}] ALL COMPLETED\n")
    return (state, state.scans_run, stage_outputs)

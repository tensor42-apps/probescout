"""
FastAPI app: POST /api/scan, GET /api/scan/status. Implementation design §0c.
Timestamps and log file are backend-only (business logic).
"""
import json
import logging
import os
import sys
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import config_loader
from guardrails import validate_target
from scan_state import ScanState
from goal import get_goal_label, get_goal_text_by_id, list_goals
from action_menu import get_action_label
from agent import run_scan
from llm_client import validate_api_key
from nmap_runner import check_sudo_nopasswd

def _log(msg: str) -> None:
    """Print to stderr so it always shows in the terminal (uvicorn may capture stdout)."""
    print(msg, file=sys.stderr, flush=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
logger = logging.getLogger(__name__)

app = FastAPI(title="ProbeScout API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def _log_requests(request, call_next):
    """Log every request so we see if POST/OPTIONS reach this process."""
    _log(f"[ProbeScout] >>> {request.method} {request.url.path}")
    response = await call_next(request)
    return response


@app.on_event("startup")
def _startup() -> None:
    pid = os.getpid()
    port = os.environ.get("PROBESCOUT_BACKEND_PORT", "12001")
    _log(f"[ProbeScout] Backend process PID={pid} (expect port {port}). If you hit Execute and see nothing here, the frontend is NOT talking to this process.")
    _log(f"[ProbeScout] Test from terminal: curl -s http://127.0.0.1:{port}/api/ping  then  curl -X POST http://127.0.0.1:{port}/api/scan -H 'Content-Type: application/json' -d '{{\"target\":\"scanme.nmap.org\"}}'")
    # Refresh LLM log and write startup banner so you can see what happened during startup
    runlogs_dir = _BACKEND_ROOT / "logs" / "runlogs"
    runlogs_dir.mkdir(parents=True, exist_ok=True)
    llm_log_path = runlogs_dir / "llm_log.txt"
    try:
        with open(llm_log_path, "w", encoding="utf-8") as f:
            f.write(f"[ProbeScout] Backend started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"[ProbeScout] Process PID={pid}. API initiated; listening (expect port {port}).\n")
            f.write(f"[ProbeScout] LLM log refreshed on startup. Request/response and constructed commands will be appended below when a scan runs.\n\n")
    except OSError as e:
        logger.warning("Could not write LLM log startup banner: %s", e)


@app.get("/api/ping")
def ping() -> dict:
    """So you can confirm requests reach this process: backend will print when this is hit."""
    _log(f"[ProbeScout] GET /api/ping -> PID={os.getpid()}")
    return {"ok": True, "pid": os.getpid()}


@app.get("/api/goals")
def get_goals() -> dict:
    """Return fixed goals for UI dropdown: list of {id, label}."""
    return {"goals": list_goals()}


# Single active scan (v1). Thread-safe.
_scan_lock = threading.Lock()
_scan_id: Optional[str] = None
_scan_status: str = "idle"
_scan_target: str = ""
_scan_step: int = 0
_scan_current_action: str = ""
_scan_stages: List[Dict[str, Any]] = []
_scan_error: Optional[str] = None
_scan_last_log: str = ""
_scan_log_lines: List[str] = []
_scan_max_steps: int = 30
_scan_final_state: Optional[Dict[str, Any]] = None  # when status=done, recon results
_scan_current_output: str = ""  # live nmap stderr (-vv) while current step is running
_scan_current_step_detail: str = ""  # e.g. "ports 22, 80" for service_detect, shown in UI
_scan_current_command: str = ""  # exact nmap command running right now (for UI)
_status_poll_count: int = 0  # for debug: log first few status polls

_BACKEND_ROOT = Path(__file__).resolve().parent


def _stage_label(action_id: str) -> str:
    return get_action_label(action_id)


def _format_results_section(results: Dict[str, Any]) -> str:
    """Human-readable results block matching frontend setResults()."""
    lines = []
    lines.append(f"Target:        {results.get('target') or '—'}")
    host = results.get('host_addr') or results.get('hostname') or '—'
    lines.append(f"Host:          {host}")
    hostname = results.get('hostname') or ''
    if hostname and hostname != (results.get('host_addr') or ''):
        lines.append(f"Hostname:      {hostname}")
    lines.append(f"Reachability:  {results.get('host_reachability') or '—'}")
    lines.append(f"OS fingerprint: {'done' if results.get('os_fingerprint_done') else '—'}")
    if results.get('os_guess'):
        lines.append(f"OS guess:      {results['os_guess']}")
    lines.append("")
    lines.append("Open ports:")
    open_ports = results.get('open_ports') or []
    if open_ports:
        for p in open_ports:
            proto = p.get('proto') or 'tcp'
            lines.append(f"  {p.get('port')}/{proto}")
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("Services:")
    services = results.get('services') or []
    if services:
        for s in services:
            proto = s.get('proto') or 'tcp'
            svc = (s.get('service') or '').strip() or '—'
            ver = (s.get('version') or '').strip()
            lines.append(f"  {s.get('port')}/{proto}: {svc}{' ' + ver if ver else ''}")
    else:
        lines.append("  (none)")
    return "\n".join(lines)


def _format_elapsed(seconds: float) -> str:
    """Format elapsed seconds as 'X m Y s' or 'Y s'."""
    if seconds < 0:
        return "—"
    if seconds < 60:
        return f"{int(round(seconds))} s"
    m = int(seconds // 60)
    s = int(round(seconds % 60))
    if s == 0:
        return f"{m} m"
    return f"{m} m {s} s"


def _build_report_text(
    target: str,
    status: str,
    step: int,
    max_steps: int,
    current_action: str,
    stages: List[Dict[str, Any]],
    last_log: str,
    log_lines: List[str],
    results: Optional[Dict[str, Any]],
    error: Optional[str],
    *,
    goal_id: Optional[str] = None,
    goal_label: Optional[str] = None,
    elapsed_seconds: Optional[float] = None,
) -> str:
    """Build human-readable report matching frontend copy-report (for saving to report.txt)."""
    step_str = f"{step} / {max_steps}" if (step is not None and max_steps is not None) else (str(step) if step is not None else "—")
    stage_count = len(stages) if stages else 0
    goal_display = f"{goal_label or goal_id or 'default'}" + (f" [{goal_id}]" if goal_id and goal_id != (goal_label or "") else "")
    progress_lines = [
        f"Target:    {target or '—'}",
        f"Goal:      {goal_display}",
        f"Status:    {status or '—'}",
        f"Steps:     {step_str}  (LLM turns, max {max_steps or '?'})",
        f"Action:    {_stage_label(current_action) if current_action else '—'}",
        f"Stages:    {stage_count}  (actions completed)",
        f"Last:      {last_log or '—'}",
    ]
    if elapsed_seconds is not None:
        progress_lines.append(f"Time taken: {_format_elapsed(elapsed_seconds)}")
    if status == "done" and step is not None and stage_count < step:
        progress_lines.append(f"Note:     Step {step} was \"done\" (end scan), so it's not in Stages.")
    if error:
        progress_lines.append(f"Error:     {error}")
    progress_text = "\n".join(progress_lines)

    stage_lines = []
    for s in stages or []:
        label = s.get("label") or _stage_label(s.get("action_id") or "")
        aid = s.get("action_id") or ""
        started = s.get("started_at") or ""
        stage_lines.append(f"{label}  {aid} {started}".strip())
    stages_text = "\n".join(stage_lines) if stage_lines else "No stages yet."

    output_parts = [s.get("output") or "" for s in (stages or []) if s.get("output")]
    output_text = "\n".join(output_parts).strip() if output_parts else "—"

    report_parts = [
        "2. Progress",
        "---",
        progress_text,
        "",
        "3. Stages (completed actions)",
        "---",
        stages_text,
        "",
        "4. Output",
        "---",
        output_text,
    ]
    if results:
        report_parts.extend(["", "5. Results", "---", _format_results_section(results), ""])
    report_parts.extend([
        "6. Log (step = LLM turn)" if results else "5. Log (step = LLM turn)",
        "---",
        "".join(log_lines).strip() if log_lines else "—",
    ])
    return "\n".join(report_parts)


def _format_started_at(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _progress_cb(
    step: int,
    state: ScanState,
    last_action_id: str,
    stage_outputs: List[tuple],
    log_message: Optional[str] = None,
    *,
    current_command: Optional[str] = None,
) -> None:
    global _scan_step, _scan_current_action, _scan_stages, _scan_last_log, _scan_current_output, _scan_current_step_detail, _scan_current_command
    with _scan_lock:
        _scan_step = step
        _scan_current_action = last_action_id
        if log_message is not None and log_message.startswith("Running:"):
            _scan_current_output = ""
            _scan_current_command = current_command or ""
            if last_action_id == "service_detect" and state.open_ports:
                _scan_current_step_detail = "ports " + ", ".join(str(p) for p, _ in state.open_ports)
            elif last_action_id and last_action_id.startswith("port_scan_"):
                _scan_current_step_detail = last_action_id.replace("port_scan_", "").replace("_", "–")
            else:
                _scan_current_step_detail = ""
        elif log_message is not None and not log_message.startswith("Running:"):
            _scan_current_step_detail = ""
            _scan_current_command = ""
        stages = []
        for item in stage_outputs:
            if len(item) == 3:
                aid, out, started_ts = item
                started_at = _format_started_at(started_ts)
            else:
                aid, out = item[0], item[1]
                started_at = None
            stages.append({
                "action_id": aid,
                "label": _stage_label(aid),
                "output": out,
                "done": True,
                "started_at": started_at,
            })
        _scan_stages = stages
        if log_message is not None:
            _scan_last_log = log_message


class ScanResponse(BaseModel):
    scan_id: str
    status: str


@app.post("/api/scan", response_model=ScanResponse)
async def post_scan(request: Request) -> ScanResponse:
    """Accept form-encoded (no CORS preflight) or JSON body."""
    global _scan_id, _scan_status, _scan_target, _scan_step, _scan_current_action, _scan_stages, _scan_error, _scan_last_log, _scan_log_lines, _scan_max_steps, _scan_final_state, _scan_current_output, _status_poll_count
    _status_poll_count = 0
    content_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if content_type == "application/json":
        body = await request.json()
        target = (body.get("target") or "").strip()
        goal_key = (body.get("goal") or "").strip() or None
    else:
        form = await request.form()
        target = (form.get("target") or "").strip()
        goal_key = (form.get("goal") or "").strip() or None
    _log(f"[ProbeScout] POST /api/scan target={target!r} goal={goal_key!r}")
    logger.info("POST /api/scan target=%r", target)
    target = validate_target(target)
    if target is None:
        raise HTTPException(status_code=400, detail="Invalid target: single hostname or IP only")
    try:
        validate_api_key()
    except (RuntimeError, ImportError, FileNotFoundError, ValueError) as e:
        raise HTTPException(status_code=503, detail=str(e))
    try:
        config_loader._load_config()
        max_steps = config_loader.get_max_steps()
        run_sudo = config_loader.get_run_nmap_sudo()
    except (FileNotFoundError, ValueError, KeyError):
        max_steps = 30
        run_sudo = False
    if not run_sudo:
        raise HTTPException(
            status_code=400,
            detail=(
                "TCP SYN scan is required. Set run_nmap_sudo: true in config/scan_config.yaml "
                "and add passwordless sudo for nmap (e.g. in /etc/sudoers.d/probescout). See config comments."
            ),
        )
    if run_sudo and not check_sudo_nopasswd():
        raise HTTPException(
            status_code=400,
            detail=(
                "Passwordless sudo for nmap is not configured. Run: sudo -n true (to test). "
                "Then add e.g. in /etc/sudoers.d/probescout: youruser ALL=(ALL) NOPASSWD: /usr/bin/nmap"
            ),
        )
    with _scan_lock:
        if _scan_status == "running":
            raise HTTPException(status_code=409, detail="A scan is already running")
        _scan_id = str(uuid.uuid4())
        _scan_status = "running"
        _scan_target = target
        _scan_step = 0
        _scan_current_action = ""
        _scan_stages = []
        _scan_error = None
        _scan_last_log = ""
        _scan_log_lines = []
        _scan_max_steps = max_steps
        _scan_final_state = None
        _scan_current_output = ""
        _scan_current_step_detail = ""
        _scan_current_command = ""

    def run() -> None:
        global _scan_status, _scan_error, _scan_log_lines, _scan_final_state, _scan_current_output, _scan_current_step_detail, _scan_current_command

        _nmap_stream_line_count = [0]  # list so inner fn can mutate

        def _on_nmap_stream(line: str) -> None:
            global _scan_current_output
            with _scan_lock:
                _scan_current_output += line
                n = _nmap_stream_line_count[0]
                _nmap_stream_line_count[0] = n + 1
                if n < 3:  # log first 3 lines so operator can confirm streaming
                    _log(f"[ProbeScout] nmap stderr #{n + 1}: {line[:80].rstrip()!r}\n")

        scan_id = _scan_id
        _log(f"[ProbeScout] Scan thread started scan_id={scan_id} target={target}")
        logger.info("Scan thread started scan_id=%s target=%s", scan_id, target)
        logs_dir = _BACKEND_ROOT / "logs"
        logs_dir.mkdir(exist_ok=True)
        log_path = logs_dir / f"scan_{scan_id}.log"
        runlogs_dir = _BACKEND_ROOT / "logs" / "runlogs"
        runlogs_dir.mkdir(parents=True, exist_ok=True)
        llm_log_path = runlogs_dir / "llm_log.txt"
        try:
            goal_label = get_goal_label(goal_key)
            with open(llm_log_path, "w", encoding="utf-8") as f:
                f.write(f"Goal: {goal_key or 'default'} ({goal_label})\n\n")
        except OSError:
            llm_log_path = None
        scan_start_time = datetime.now()
        try:
            with open(log_path, "w", encoding="utf-8") as log_file:
                def log_cb(line: str) -> None:
                    with _scan_lock:
                        _scan_log_lines.append(line)
                    log_file.write(line)
                    log_file.flush()

                goal_text_override = get_goal_text_by_id(goal_key) if goal_key else None
                _log(f"[ProbeScout] Calling run_scan target={target} goal={goal_key or 'default'}")
                logger.info("Calling run_scan target=%s goal=%s", target, goal_key or "default")
                state, _, stage_outputs = run_scan(
                    target_override=target,
                    progress_callback=_progress_cb,
                    log_callback=log_cb,
                    output_stream_callback=_on_nmap_stream,
                    llm_log_path=llm_log_path,
                    goal_text_override=goal_text_override,
                    goal_id=goal_key,
                )
                logger.info("run_scan finished scan_id=%s", scan_id)
                with _scan_lock:
                    stages_for_json = [
                        {
                            "action_id": item[0],
                            "output": item[1],
                            "started_at": _format_started_at(item[2]) if len(item) >= 3 else None,
                        }
                        for item in stage_outputs
                    ]
                    _scan_final_state = {
                        "scan_id": scan_id,
                        "target": state.target,
                        "goal": goal_key or "default",
                        "goal_label": get_goal_label(goal_key),
                        "host_reachability": state.host_reachability,
                        "host_addr": state.host_addr,
                        "hostname": state.hostname,
                        "open_ports": [{"port": p, "proto": proto} for p, proto in state.open_ports],
                        "services": [
                            {"port": p, "proto": proto, "service": svc or "", "version": ver or ""}
                            for p, proto, svc, ver in state.services
                        ],
                        "os_fingerprint_done": state.os_fingerprint_done,
                        "os_guess": state.os_guess,
                        "scans_run": state.scans_run,
                        "stages": stages_for_json,
                    }
                # Final report: one JSON file per run (canonical for reporting; includes raw nmap output per stage).
                results_path = logs_dir / f"scan_{scan_id}_results.json"
                try:
                    with open(results_path, "w", encoding="utf-8") as f:
                        json.dump(_scan_final_state, f, indent=2)
                except OSError as e:
                    logger.warning("Could not write results JSON %s: %s", results_path, e)
                # Human-readable report in runlogs (same location as llm_log.txt) for validation.
                report_path = runlogs_dir / "report.txt"
                llm_log_path_canonical = runlogs_dir / "llm_log.txt"
                elapsed_seconds = (datetime.now() - scan_start_time).total_seconds()
                try:
                    report_text = _build_report_text(
                        _scan_target,
                        "done",
                        _scan_step,
                        _scan_max_steps,
                        _scan_current_action,
                        _scan_stages,
                        _scan_last_log,
                        _scan_log_lines,
                        _scan_final_state,
                        None,
                        goal_id=goal_key,
                        goal_label=get_goal_label(goal_key),
                        elapsed_seconds=elapsed_seconds,
                    )
                    report_text += f"\n\nreport: {report_path.resolve()}\nlog: {llm_log_path_canonical.resolve()}"
                    with open(report_path, "w", encoding="utf-8") as f:
                        f.write(report_text)
                except OSError as e:
                    logger.warning("Could not write report.txt %s: %s", report_path, e)
        except Exception as e:
            _log(f"[ProbeScout] Scan thread FAILED: {e}")
            logger.exception("Scan thread failed: %s", e)
            with _scan_lock:
                _scan_error = str(e)
                _scan_status = "error"
            return
        with _scan_lock:
            _scan_status = "done"

    t = threading.Thread(target=run, daemon=True)
    t.start()
    logger.info("POST /api/scan returning 200 scan_id=%s", _scan_id)
    return ScanResponse(scan_id=_scan_id, status="running")


@app.get("/api/scan/status")
def get_scan_status() -> dict:
    global _status_poll_count
    with _scan_lock:
        _status_poll_count += 1
        out_len = len(_scan_current_output)
        if _status_poll_count <= 10 or (_scan_status == "running" and out_len > 0):
            _log(f"[ProbeScout] GET /api/scan/status #{_status_poll_count} -> status={_scan_status} current_step_output_len={out_len}\n")
        # step = current LLM turn (1-based). stages = list of completed actions (host_reachability, port_scan_*, etc.).
        data = {
            "scan_id": _scan_id,
            "target": _scan_target,
            "status": _scan_status,
            "step": _scan_step,
            "max_steps": _scan_max_steps,
            "current_action": _scan_current_action,
            "stages": list(_scan_stages),
            "last_log": _scan_last_log,
            "log_lines": list(_scan_log_lines),
            "steps_meaning": "LLM decision rounds (ask model → run action).",
            "stages_meaning": "Completed actions (e.g. host check, port scan).",
            **({"results": _scan_final_state} if _scan_status == "done" and _scan_final_state else {}),
            **({"current_step_output": _scan_current_output, "current_step_detail": _scan_current_step_detail, "current_command": _scan_current_command} if _scan_status == "running" else {}),
            **({"error": _scan_error} if _scan_error else {}),
        }
    return data

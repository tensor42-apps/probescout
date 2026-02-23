"""
FastAPI app: POST /api/scan, GET /api/scan/status. Implementation design §0c.
Timestamps and log file are backend-only (business logic).
"""
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
from agent import run_scan
from llm_client import validate_api_key

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


@app.get("/api/ping")
def ping() -> dict:
    """So you can confirm requests reach this process: backend will print when this is hit."""
    _log(f"[ProbeScout] GET /api/ping -> PID={os.getpid()}")
    return {"ok": True, "pid": os.getpid()}

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
_status_poll_count: int = 0  # for debug: log first few status polls

_BACKEND_ROOT = Path(__file__).resolve().parent


def _stage_label(action_id: str) -> str:
    labels = {
        "host_reachability": "Host reachability",
        "port_scan_1_100": "Port scan 1–100",
        "port_scan_1_1000": "Port scan 1–1000",
        "port_scan_1_65535": "Port scan 1–65535",
        "service_detect": "Service detection",
        "os_fingerprint": "OS fingerprint",
        "wait": "Wait",
        "done": "Done",
    }
    return labels.get(action_id, action_id)


def _format_started_at(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _progress_cb(
    step: int,
    state: ScanState,
    last_action_id: str,
    stage_outputs: List[tuple],
    log_message: Optional[str] = None,
) -> None:
    global _scan_step, _scan_current_action, _scan_stages, _scan_last_log
    with _scan_lock:
        _scan_step = step
        _scan_current_action = last_action_id
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
    global _scan_id, _scan_status, _scan_target, _scan_step, _scan_current_action, _scan_stages, _scan_error, _scan_last_log, _scan_log_lines, _scan_max_steps, _status_poll_count
    _status_poll_count = 0
    content_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if content_type == "application/json":
        body = await request.json()
        target = (body.get("target") or "").strip()
    else:
        # application/x-www-form-urlencoded or missing
        form = await request.form()
        target = (form.get("target") or "").strip()
    _log(f"[ProbeScout] POST /api/scan target={target!r}")
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
    except (FileNotFoundError, ValueError, KeyError):
        max_steps = 30
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

    def run() -> None:
        global _scan_status, _scan_error, _scan_log_lines
        scan_id = _scan_id
        _log(f"[ProbeScout] Scan thread started scan_id={scan_id} target={target}")
        logger.info("Scan thread started scan_id=%s target=%s", scan_id, target)
        logs_dir = _BACKEND_ROOT / "logs"
        logs_dir.mkdir(exist_ok=True)
        log_path = logs_dir / f"scan_{scan_id}.log"
        try:
            with open(log_path, "w", encoding="utf-8") as log_file:
                def log_cb(line: str) -> None:
                    with _scan_lock:
                        _scan_log_lines.append(line)
                    log_file.write(line)
                    log_file.flush()

                _log(f"[ProbeScout] Calling run_scan target={target}")
                logger.info("Calling run_scan target=%s", target)
                run_scan(
                    target_override=target,
                    progress_callback=_progress_cb,
                    log_callback=log_cb,
                )
                logger.info("run_scan finished scan_id=%s", scan_id)
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
        if _status_poll_count <= 5:
            _log(f"[ProbeScout] GET /api/scan/status #{_status_poll_count} -> status={_scan_status}")
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
            **({"error": _scan_error} if _scan_error else {}),
        }
    return data

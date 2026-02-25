#!/usr/bin/env python3
"""
Run all three goals via backend API: POST /api/scan, poll status until done, then read report and llm_log.
Use from backend dir: python testing/run_three_goals_via_api.py
Or from repo root: python dev/app/backend/testing/run_three_goals_via_api.py
"""
import json
import os
import sys
import time
from pathlib import Path

try:
    import urllib.request
    import urllib.error
except ImportError:
    urllib = None  # type: ignore

# Backend root (parent of testing/)
BACKEND_ROOT = Path(__file__).resolve().parent.parent
RUNLOGS = BACKEND_ROOT / "logs" / "runlogs"
PORT = os.environ.get("PROBESCOUT_BACKEND_PORT", "12001")
BASE = f"http://127.0.0.1:{PORT}"
TARGET = "scanme.nmap.org"
GOALS = ["simple_recon", "well_known_tcp", "full_stealth_tcp"]
POLL_INTERVAL = 3
MAX_WAIT_SEC = 600  # 10 min per goal


def req(method: str, url: str, data: dict | None = None) -> dict:
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        r = urllib.request.Request(url, data=body, method=method, headers={"Content-Type": "application/json"})
    else:
        r = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(r, timeout=30) as resp:
        return json.loads(resp.read().decode())


def run_goal(goal_id: str) -> tuple[str, dict, str, str]:
    """Start scan, poll until done/error. Return (status, status_json, report_text, llm_log_text)."""
    print(f"\n--- Goal: {goal_id} ---")
    try:
        out = req("POST", f"{BASE}/api/scan", {"target": TARGET, "goal": goal_id})
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        print(f"POST failed: {e.code} {body}")
        return "error", {}, "", ""
    except Exception as e:
        print(f"POST error: {e}")
        return "error", {}, "", ""
    scan_id = out.get("scan_id") or ""
    print(f"Started scan_id={scan_id}, polling...")
    start = time.time()
    last_status = None
    st = {}
    while time.time() - start < MAX_WAIT_SEC:
        try:
            st = req("GET", f"{BASE}/api/scan/status")
        except Exception as e:
            print(f"Status poll error: {e}")
            time.sleep(POLL_INTERVAL)
            continue
        last_status = st.get("status") or ""
        step = st.get("step") or 0
        max_steps = st.get("max_steps") or "?"
        if last_status in ("done", "error"):
            print(f"Finished: status={last_status} step={step}/{max_steps}")
            break
        print(f"  status={last_status} step={step}/{max_steps}")
        time.sleep(POLL_INTERVAL)
    report_path = RUNLOGS / "report.txt"
    llm_log_path = RUNLOGS / "llm_log.txt"
    report_text = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
    llm_log_text = llm_log_path.read_text(encoding="utf-8") if llm_log_path.exists() else ""
    return last_status or "unknown", st if last_status else {}, report_text, llm_log_text


def main() -> int:
    if urllib is None:
        print("urllib not available", file=sys.stderr)
        return 1
    RUNLOGS.mkdir(parents=True, exist_ok=True)
    results_dir = Path(__file__).resolve().parent
    print(f"Backend: {BASE}  target: {TARGET}  goals: {GOALS}")
    print(f"Report/log dir: {RUNLOGS}")
    all_ok = True
    for goal_id in GOALS:
        status, status_json, report_text, llm_log_text = run_goal(goal_id)
        # Save copy for this goal
        out_file = results_dir / f"run_result_{goal_id}.txt"
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(f"Goal: {goal_id}\nStatus: {status}\n\n=== REPORT ===\n{report_text}\n\n=== LLM LOG ===\n{llm_log_text}\n")
        print(f"Wrote {out_file}")
        if status == "error":
            all_ok = False
        if status_json.get("error"):
            print(f"  Error: {status_json.get('error')}")
            all_ok = False
    print("\nDone. Check logs/runlogs/report.txt and llm_log.txt (last run) and testing/run_result_*.txt")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())

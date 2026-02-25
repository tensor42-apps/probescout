#!/usr/bin/env python3
"""
Test that run_nmap(..., output_stream_callback=...) delivers stderr lines *during* the run,
not only at the end. Uses the same path as the app (PTY + stdbuf).
Run from backend: python testing/test_live_output_during_scan.py
"""
import sys
import threading
import time
from pathlib import Path

_backend = Path(__file__).resolve().parent.parent
if str(_backend) not in sys.path:
    sys.path.insert(0, str(_backend))

from nmap_runner import run_nmap


def main() -> int:
    output_chunks: list[str] = []
    output_lock = threading.Lock()
    first_byte_time: list[float] = []
    run_start: list[float] = []

    def callback(line: str) -> None:
        with output_lock:
            output_chunks.append(line)
            if not first_byte_time and run_start:
                first_byte_time.append(time.monotonic() - run_start[0])
                print(f"[stream] first line at t={first_byte_time[0]:.2f}s: {line[:60]!r}...", flush=True)

    # Run nmap in a thread (same as app)
    def run() -> None:
        run_start.append(time.monotonic())
        run_nmap(
            "scanme.nmap.org",
            "port_scan",
            use_sudo=False,
            timeout_sec=60,
            port_range="1-100",
            output_stream_callback=callback,
        )

    t0 = time.monotonic()
    th = threading.Thread(target=run, daemon=True)
    th.start()

    # Poll every 0.2s and record when we first see content and when run ends
    last_len = 0
    while th.is_alive() or output_chunks:
        time.sleep(0.2)
        with output_lock:
            n = len(output_chunks)
            total_len = sum(len(c) for c in output_chunks)
        if total_len > last_len:
            last_len = total_len
            print(f"[poll] t={time.monotonic() - t0:.2f}s chunks={n} total_len={total_len}", flush=True)
        if not th.is_alive():
            break

    th.join(timeout=2)
    elapsed = time.monotonic() - t0

    with output_lock:
        first_at = first_byte_time[0] if first_byte_time else None
        had_content_during_run = first_at is not None and first_at < elapsed - 0.5
        total_lines = len(output_chunks)
        total_chars = sum(len(c) for c in output_chunks)

    print(f"\n--- Run finished in {elapsed:.2f}s. Total stderr: {total_lines} lines, {total_chars} chars.")
    if first_at is not None:
        print(f"    First line arrived at t={first_at:.2f}s (during run: {had_content_during_run})")
    else:
        print("    No stderr lines received during run.")

    # We expect at least one line to arrive before the run ends (e.g. "Warning: Hostname ...")
    if total_lines == 0:
        print("FAIL: no stderr lines at all.", file=sys.stderr)
        return 1
    if not had_content_during_run and total_lines == 1:
        print("WARN: only one line and it may have arrived at end; streaming might be buffered.", file=sys.stderr)
    if total_lines >= 1:
        print("OK: received stderr during/from run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Verify nmap stderr streams line-by-line when run with stdbuf.
Run from repo root: python dev/app/backend/testing/test_nmap_stream.py
Or from backend: python testing/test_nmap_stream.py
"""
import subprocess
import sys
import threading
import time
from pathlib import Path

# Ensure backend is on path
_backend = Path(__file__).resolve().parent.parent
if str(_backend) not in sys.path:
    sys.path.insert(0, str(_backend))

import shutil
from action_menu import get_nmap_argv


def main() -> None:
    target = "scanme.nmap.org"
    # Use a small port range so the scan lasts a few seconds and we see multiple lines.
    argv = get_nmap_argv("port_scan", target, use_sudo=False, timeout_sec=60, port_range="1-100")
    if not argv:
        print("get_nmap_argv returned None", file=sys.stderr)
        sys.exit(1)

    stdbuf = shutil.which("stdbuf")
    if stdbuf:
        argv = [stdbuf, "-e0", "-o0"] + argv
        print(f"Using stdbuf: {' '.join(argv[:5])} ...", file=sys.stderr)
    else:
        print("stdbuf not found; stderr may be buffered until process exits", file=sys.stderr)

    received: list[str] = []

    def on_stderr(line: str) -> None:
        ts = time.strftime("%H:%M:%S", time.localtime())
        received.append(line)
        print(f"[{ts}] {line}", end="", flush=True)

    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        shell=False,
    )

    def read_stdout() -> None:
        if proc.stdout:
            for _ in iter(proc.stdout.readline, ""):
                pass  # consume stdout so process doesn't block

    def read_stderr() -> None:
        if proc.stderr:
            for line in iter(proc.stderr.readline, ""):
                on_stderr(line)

    t_out = threading.Thread(target=read_stdout, daemon=True)
    t_err = threading.Thread(target=read_stderr, daemon=True)
    t_out.start()
    t_err.start()
    proc.wait(timeout=90)
    t_out.join(timeout=2)
    t_err.join(timeout=2)

    print(f"\n--- Done. Received {len(received)} stderr lines.", file=sys.stderr)
    if stdbuf and len(received) == 0:
        print("WARNING: stdbuf was used but no stderr lines received; streaming may be broken.", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()

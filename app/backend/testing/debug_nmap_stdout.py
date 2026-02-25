#!/usr/bin/env python3
"""
Minimal repro: run the exact nmap command the backend runs (port_scan with -oX -),
using the same Popen + PTY + threads setup as nmap_runner. Print xml_stdout length
and parsed open ports. Run from backend dir: python3 testing/debug_nmap_stdout.py
"""
import os
import sys
from pathlib import Path

# backend root
BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import subprocess
import threading

def main():
    from action_menu import get_nmap_argv

    argv = get_nmap_argv(
        "port_scan",
        "scanme.nmap.org",
        use_sudo=True,
        timeout_sec=300,
        port_range="1-1024",
    )
    if not argv:
        print("get_nmap_argv returned None")
        return 1
    print("argv:", argv[:6], "...")
    run_timeout = 300 + 60

    try:
        import pty as pty_mod
    except ImportError:
        print("PTY not available, using PIPE for both")
        pty_mod = None

    stdout_chunks = []
    stderr_chunks = []

    if pty_mod:
        master_fd, slave_fd = pty_mod.openpty()
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=slave_fd,
                text=False,
                shell=False,
                start_new_session=True,
            )
            os.close(slave_fd)

            def read_stdout():
                if proc.stdout:
                    while True:
                        chunk = proc.stdout.read(65536)
                        if not chunk:
                            break
                        stdout_chunks.append(chunk)

            def read_stderr():
                while True:
                    try:
                        data = os.read(master_fd, 4096)
                    except OSError:
                        break
                    if not data:
                        break
                    stderr_chunks.append(data.decode("utf-8", errors="replace"))

            t1 = threading.Thread(target=read_stdout, daemon=True)
            t2 = threading.Thread(target=read_stderr, daemon=True)
            t1.start()
            t2.start()
            proc.wait(timeout=run_timeout)
            try:
                os.close(master_fd)
            except OSError:
                pass
            t1.join(timeout=10)
            t2.join(timeout=5)
            xml_out = b"".join(stdout_chunks).decode("utf-8", errors="replace")
            returncode = proc.returncode or 0
        finally:
            try:
                os.close(master_fd)
            except OSError:
                pass
            try:
                os.close(slave_fd)
            except OSError:
                pass
    else:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            shell=False,
        )
        out, _ = proc.communicate(timeout=run_timeout)
        xml_out = (out or b"").decode("utf-8", errors="replace")
        returncode = proc.returncode or 0

    print(f"returncode: {returncode}")
    print(f"xml_stdout length: {len(xml_out)}")
    if xml_out:
        print(f"xml_stdout starts with: {repr(xml_out[:150])}")
        # Parse for open ports
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(xml_out)
            open_ports = []
            for host in root.findall(".//host"):
                ports_el = host.find("ports")
                if ports_el is None:
                    continue
                for port_el in ports_el.findall("port"):
                    portid = port_el.get("portid")
                    state_el = port_el.find("state")
                    st = (state_el.get("state") or "").lower() if state_el is not None else ""
                    if portid and st == "open":
                        open_ports.append((portid, port_el.get("protocol", "tcp")))
            print(f"Parsed open ports: {open_ports}")
        except ET.ParseError as e:
            print(f"XML parse error: {e}")
    else:
        print("stderr sample:", "".join(stderr_chunks)[:500] if stderr_chunks else "(none)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

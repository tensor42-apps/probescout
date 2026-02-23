"""
CLI entrypoint: run_scan from config target, print result. Implementation design §9, §10.
"""
import sys
import json

from agent import run_scan
from scan_state import ScanState


def print_result(state: ScanState, scans_run: list) -> None:
    print("--- Scan complete ---")
    print("Scans run:", ", ".join(scans_run))
    print("Target:", state.target)
    print("Host reachability:", state.host_reachability)
    if state.open_ports:
        print("Open ports:", ", ".join(f"{p}/{proto}" for p, proto in state.open_ports))
    if state.services:
        for port, proto, svc, ver in state.services:
            print(f"  {port}/{proto}: {svc or '?'} {ver or ''}")
    print("OS fingerprint done:", state.os_fingerprint_done)
    out = {
        "target": state.target,
        "host_reachability": state.host_reachability,
        "open_ports": state.open_ports,
        "services": [
            {"port": p, "protocol": proto, "service": s, "version": v}
            for p, proto, s, v in state.services
        ],
        "os_fingerprint_done": state.os_fingerprint_done,
        "scans_run": state.scans_run,
    }
    print("\nJSON:", json.dumps(out, indent=2))


def main() -> int:
    try:
        state, scans_run, _ = run_scan()
        print_result(state, scans_run)
        return 0
    except FileNotFoundError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"Pre-flight error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

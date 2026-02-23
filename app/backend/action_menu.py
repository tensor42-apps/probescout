"""
Action menu and engine mapping: allowed action_ids and nmap argv. Implementation design §4, §10.
"""
from typing import List, Optional

from scan_state import ScanState, goal_achieved

ALL_ACTION_IDS = [
    "host_reachability",
    "wait",
    "done",
    "port_scan_1_100",
    "port_scan_1_1000",
    "port_scan_1_65535",
    "service_detect",
    "os_fingerprint",
]

DEFAULT_TIMEOUT = 300


def get_current_menu(state: ScanState) -> List[str]:
    # When goal is achieved, only offer "done" so the run ends (no repeated os_fingerprint/wait).
    if goal_achieved(state):
        return ["done"]
    if not state.scans_run:
        return ["host_reachability", "wait"]
    if state.host_reachability == "no_response":
        return ["wait", "done"]
    return [
        "port_scan_1_100",
        "port_scan_1_1000",
        "port_scan_1_65535",
        "service_detect",
        "os_fingerprint",
        "wait",
    ]


def get_nmap_argv(
    action_id: str,
    target: str,
    use_sudo: bool,
    timeout_sec: int = DEFAULT_TIMEOUT,
) -> Optional[List[str]]:
    """Return argv for subprocess (including nmap binary and target). None for wait/done."""
    if action_id == "host_reachability":
        base = ["nmap", "-sn", "-vv", f"--host-timeout={timeout_sec}", "-oX", "-", target]
        if use_sudo:
            return ["sudo", "-n", "nmap", "-sn", "-vv", f"--host-timeout={timeout_sec}", "-oX", "-", target]
        return base
    if action_id == "port_scan_1_100":
        base = ["nmap", "-sS", "-p", "1-100", "-T4", "-vv", "--host-timeout", str(timeout_sec), "-oX", "-", target]
        if use_sudo:
            return ["sudo", "-n", "nmap", "-sS", "-p", "1-100", "-T4", "-vv", "--host-timeout", str(timeout_sec), "-oX", "-", target]
        return base
    if action_id == "port_scan_1_1000":
        base = ["nmap", "-sS", "-p", "1-1000", "-T4", "-vv", "--host-timeout", str(timeout_sec), "-oX", "-", target]
        if use_sudo:
            return ["sudo", "-n", "nmap", "-sS", "-p", "1-1000", "-T4", "-vv", "--host-timeout", str(timeout_sec), "-oX", "-", target]
        return base
    if action_id == "port_scan_1_65535":
        base = ["nmap", "-sS", "-p", "1-65535", "-T4", "-vv", "--host-timeout", str(timeout_sec), "-oX", "-", target]
        if use_sudo:
            return ["sudo", "-n", "nmap", "-sS", "-p", "1-65535", "-T4", "-vv", "--host-timeout", str(timeout_sec), "-oX", "-", target]
        return base
    if action_id == "service_detect":
        base = ["nmap", "-sS", "-sV", "-p", "1-65535", "-T4", "-vv", "--host-timeout", str(timeout_sec), "-oX", "-", target]
        if use_sudo:
            return ["sudo", "-n", "nmap", "-sS", "-sV", "-p", "1-65535", "-T4", "-vv", "--host-timeout", str(timeout_sec), "-oX", "-", target]
        return base
    if action_id == "os_fingerprint":
        base = ["nmap", "-O", "-vv", f"--host-timeout={timeout_sec}", "-oX", "-", target]
        if use_sudo:
            return ["sudo", "-n", "nmap", "-O", "-vv", f"--host-timeout={timeout_sec}", "-oX", "-", target]
        return base
    return None

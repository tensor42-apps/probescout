"""
Intent-to-action mapping and nmap argv. Truly agentic: AI proposes intents (e.g. port_scan with any range); we validate and map to action_id.
Implementation design §4, §10.
"""
import re
import shutil
from typing import Any, Dict, List, Optional, Tuple


def _nmap_bin() -> str:
    """Full path to nmap so sudo invocations match sudoers (e.g. NOPASSWD: /usr/bin/nmap)."""
    return shutil.which("nmap") or "/usr/bin/nmap"


def command_for_display(argv: List[str]) -> str:
    """Command line for logs/UI/report: same as argv but without -oX - (XML is for backend parsing only)."""
    out: List[str] = []
    i = 0
    while i < len(argv):
        if i + 1 < len(argv) and argv[i] == "-oX" and argv[i + 1] == "-":
            i += 2
            continue
        out.append(argv[i])
        i += 1
    return " ".join(out)

from goal import goal_achieved, is_port_scan_goal
from scan_state import ScanState

# Allowed intents (AI proposes one of these; we map to action_id).
ALLOWED_INTENTS = frozenset(("host_reachability", "port_scan", "service_detect", "os_fingerprint", "done"))

# service_detect: AI sends scope "all" | "common" -> action_id.
SERVICE_SCOPE_TO_ACTION = {"all": "service_detect", "common": "service_detect_common"}

# Actions that require SYN scan (-sS) and thus run_nmap_sudo: true.
_SYN_SCAN_ACTIONS = frozenset(("port_scan", "service_detect", "service_detect_common"))

COMMON_PORTS = frozenset((22, 80, 443, 8080, 8443))

ACTION_LABELS = {
    "host_reachability": "Host reachability",
    "done": "Done",
    "port_scan": "Port scan",
    "service_detect": "Service detection (all open ports)",
    "service_detect_common": "Service detection (common ports)",
    "os_fingerprint": "OS fingerprint",
}

# Nmap -p format: digits, commas, hyphens only; each port 1-65535.
_PORT_RANGE_RE = re.compile(r"^[\d,\-]+$")
_MAX_PORT = 65535


def _validate_port_range(value: str) -> Optional[str]:
    """Validate and return normalized port range for nmap -p, or None if invalid."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s or not _PORT_RANGE_RE.match(s):
        return None
    for part in re.split(r"[,]", s):
        part = part.strip()
        if not part:
            return None
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                low, high = int(a.strip()), int(b.strip())
                if low < 1 or high > _MAX_PORT or low > high:
                    return None
            except ValueError:
                return None
        else:
            try:
                p = int(part)
                if p < 1 or p > _MAX_PORT:
                    return None
            except ValueError:
                return None
    return s


def get_action_label(action_id: str) -> str:
    return ACTION_LABELS.get(action_id, action_id)


DEFAULT_TIMEOUT = 300
OS_DETECT_CLOSED_PORT = 44444


def intent_to_action_id(
    intent: str, params: Dict[str, Any], state: ScanState, goal_id: Optional[str] = None
) -> Optional[str]:
    """
    Validate (intent, params) against state and map to allowlisted action_id. None if invalid.
    goal_id: for per-goal completion (e.g. full_stealth_tcp achieved after port_scan only).
    """
    if goal_achieved(state, goal_id) and intent != "done":
        return None
    intent = (intent or "").strip().lower()
    if intent not in ALLOWED_INTENTS:
        return None
    if intent == "done":
        return "done"
    if intent == "host_reachability":
        if is_port_scan_goal(goal_id):
            return None  # port-scan goals do not use host_reachability
        return "host_reachability"
    if intent == "os_fingerprint":
        return "os_fingerprint"
    if intent == "port_scan":
        range_val = (params.get("range") or params.get("port_range") or "").strip()
        if not _validate_port_range(range_val):
            return None
        return "port_scan"
    if intent == "service_detect":
        if not state.open_ports:
            return None
        scope = (params.get("scope") or "all").strip().lower()
        action_id = SERVICE_SCOPE_TO_ACTION.get(scope, "service_detect")
        if action_id == "service_detect_common" and not any(p in COMMON_PORTS for p, _ in state.open_ports):
            return None
        return action_id
    return None


def get_nmap_argv(
    action_id: str,
    target: str,
    use_sudo: bool,
    timeout_sec: int = DEFAULT_TIMEOUT,
    open_ports: Optional[List[Tuple[int, str]]] = None,
    port_range: Optional[str] = None,
) -> Optional[List[str]]:
    """Return argv for subprocess (including nmap binary and target). None for done.
    open_ports: when set, service_detect uses only these ports (e.g. from a prior port scan).
    port_range: for action_id port_scan, the -p argument (e.g. '1-1024', '22,80,443'). Must be pre-validated.
    """
    nmap_path = _nmap_bin()
    if action_id == "host_reachability":
        # Host discovery (-sn) does not need root; always run without sudo so stdout/XML is reliable and env matches CLI.
        return [nmap_path, "-sn", "-vv", f"--host-timeout={timeout_sec}", "-oX", "-", target]
    # SYN scan (-sS) only: port scans and service_detect require root (run_nmap_sudo: true).
    if action_id in _SYN_SCAN_ACTIONS and not use_sudo:
        raise RuntimeError(
            "TCP SYN scan (-sS) is required for port scans and service detection. "
            "Set run_nmap_sudo: true in config and ensure passwordless sudo for nmap."
        )
    scan_opt = "-sS"
    if action_id == "port_scan":
        p_arg = _validate_port_range(port_range or "") if port_range else None
        if not p_arg:
            return None
        return ["sudo", "-n", nmap_path, scan_opt, "-p", p_arg, "-T4", "-vv", "--host-timeout", str(timeout_sec), "-oX", "-", target]
    if action_id == "service_detect":
        # Service detection only on already-discovered open ports when we have them; else full range.
        if open_ports:
            port_arg = ",".join(str(p) for p in sorted(set(p for p, _ in open_ports)))
        else:
            port_arg = "1-65535"
        return ["sudo", "-n", nmap_path, scan_opt, "-sV", "-p", port_arg, "-T4", "-vv", "--host-timeout", str(timeout_sec), "-oX", "-", target]
    if action_id == "service_detect_common":
        # Service detection on common ports only (subset of open_ports).
        if open_ports:
            common_open = sorted(set(p for p, _ in open_ports if p in COMMON_PORTS))
            port_arg = ",".join(str(p) for p in common_open) if common_open else ",".join(str(p) for p in sorted(set(p for p, _ in open_ports)))
        else:
            port_arg = "22,80,443,8080,8443"
        return ["sudo", "-n", nmap_path, scan_opt, "-sV", "-p", port_arg, "-T4", "-vv", "--host-timeout", str(timeout_sec), "-oX", "-", target]
    if action_id == "os_fingerprint":
        # Use a few open ports + one closed port for faster OS detection when we have open ports.
        if open_ports:
            ports = sorted(set(p for p, _ in open_ports))[:3]
            ports.append(OS_DETECT_CLOSED_PORT)
            port_arg = ",".join(str(p) for p in sorted(set(ports)))
            base = [nmap_path, "-O", "-p", port_arg, "-vv", f"--host-timeout={timeout_sec}", "-oX", "-", target]
        else:
            base = [nmap_path, "-O", "-vv", f"--host-timeout={timeout_sec}", "-oX", "-", target]
        if use_sudo:
            args = ["sudo", "-n", nmap_path, "-O"]
            if open_ports:
                args.extend(["-p", port_arg])
            args.extend(["-vv", f"--host-timeout={timeout_sec}", "-oX", "-", target])
            return args
        return base
    return None

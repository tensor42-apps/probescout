"""
Goal definition: what we want and when we're done. Fixed goals for UI dropdown; AI proposes intents.
Canonical list (name + description): goal.md. Here: id, label (name in UI), text (prompt).
"""
from typing import List, Optional

from scan_state import ScanState

# Reply format only (how to respond), not strategy. AI decides approach.
_INTENT_SCHEMA = (
    " Reply with a JSON object: \"intent\" (host_reachability, port_scan, service_detect, os_fingerprint, done), "
    "params when needed: for port_scan \"range\" (e.g. \"1-1024\", \"22,80,443\", \"1-65535\"); "
    "for service_detect \"scope\" (all or common). Include \"reason\". Optional: \"reasoning\", \"plan\"."
)
# For port-scan goals: no host_reachability; go straight to port_scan (or service_detect, os_fingerprint, done).
_INTENT_SCHEMA_PORT_SCAN = (
    " Reply with a JSON object: \"intent\" (port_scan, service_detect, os_fingerprint, done), "
    "params when needed: for port_scan \"range\" (e.g. \"1-1024\", \"22,80,443\", \"1-65535\"); "
    "for service_detect \"scope\" (all or common). Include \"reason\". Optional: \"reasoning\", \"plan\"."
)

# Goals that skip host_reachability entirely (port-scan only).
PORT_SCAN_GOAL_IDS = frozenset((
    "well_known_tcp",
    "full_stealth_tcp",
    "quick_top_ports",
    "common_ports",
    "web_ports",
    "compliance_ports",
))

# When is this goal achieved? "full" = host + service_detect + os_fingerprint; "port_scan_only" = at least one port_scan; "port_scan_and_services" = port_scan + service_detect (no OS required).
GOALS = [
    {
        "id": "simple_recon",
        "label": "Simple recon scan",
        "description": "Host check, port scan, service detection, and OS fingerprint. You choose the steps.",
        "text": "Do a simple recon on the target. You decide the steps and approach." + _INTENT_SCHEMA,
        "achieved_when": "full",
    },
    {
        "id": "well_known_tcp",
        "label": "Well known TCP scan",
        "description": "Ports 1–1024 only, then optional service/OS. Skips host ping. Good default for a first scan.",
        "text": (
            "Do a well-known TCP port scan on the target. "
            "Well-known typically means ports 1-1024 (IANA well-known and registered). "
            "Do not use host_reachability; go straight to port_scan. You decide the steps and approach."
            + _INTENT_SCHEMA_PORT_SCAN
        ),
        "achieved_when": "full",
    },
    {
        "id": "full_stealth_tcp",
        "label": "Full Stealth TCP scan on all ports",
        "description": "All 65k TCP ports (can take 45–60 min). Skips host ping. Stops after port scan; no service/OS required.",
        "text": (
            "Do a full stealth TCP scan on all ports. "
            "Do not use host_reachability; go straight to port_scan. You decide the steps and approach."
            + _INTENT_SCHEMA_PORT_SCAN
        ),
        "achieved_when": "port_scan_only",
    },
    {
        "id": "quick_top_ports",
        "label": "Quick top ports",
        "description": "Small set of high-value ports (22, 80, 443, 21, 25, 53, 8080, 8443, 3389…). Under a minute; optional service detection.",
        "text": (
            "Scan only a small, fixed set of high-value ports (e.g. 22, 80, 443, 21, 25, 53, 8080, 8443, 3389). "
            "Fast first look in under a minute; then optionally run service_detect. "
            "Do not use host_reachability; go straight to port_scan."
            + _INTENT_SCHEMA_PORT_SCAN
        ),
        "achieved_when": "port_scan_only",
    },
    {
        "id": "common_ports",
        "label": "Common service ports",
        "description": "FTP, SSH, SMTP, DNS, HTTP, POP3, IMAP, HTTPS, 8080, 8443 + service/version detection.",
        "text": (
            "Scan common service ports (FTP 21, SSH 22, SMTP 25, DNS 53, HTTP 80, POP3 110, IMAP 143, HTTPS 443, 8080, 8443) "
            "and run service detection. Fast check for typical services and versions. "
            "Do not use host_reachability; go straight to port_scan, then run service_detect (scope all or common)."
            + _INTENT_SCHEMA_PORT_SCAN
        ),
        "achieved_when": "port_scan_and_services",
    },
    {
        "id": "web_ports",
        "label": "Web server ports",
        "description": "Ports 80, 443, 8080, 8443, 8000, 8888 + service detection to identify web stack and versions.",
        "text": (
            "Scan web-related ports only (80, 443, 8080, 8443, 8000, 8888) and run service detection. "
            "Goal: identify web stack and versions for follow-up HTTP(s) testing. "
            "Do not use host_reachability; go straight to port_scan on these ports, then service_detect."
            + _INTENT_SCHEMA_PORT_SCAN
        ),
        "achieved_when": "port_scan_and_services",
    },
    {
        "id": "compliance_ports",
        "label": "Policy / compliance ports",
        "description": "Fixed policy set (e.g. 22, 80, 443, 3389, 5985) + version detection for baselines or compliance.",
        "text": (
            "Scan a fixed policy set (e.g. 22, 80, 443, 3389, 5985) and run version detection. "
            "For we only care about these ports or baseline compliance. "
            "Do not use host_reachability; go straight to port_scan, then service_detect."
            + _INTENT_SCHEMA_PORT_SCAN
        ),
        "achieved_when": "port_scan_and_services",
    },
    {
        "id": "external_perimeter",
        "label": "External perimeter recon",
        "description": "Simulate external attacker: host check → port scan → service detection → OS fingerprint. Full perimeter test.",
        "text": (
            "Simulate an external attacker: run host reachability, then port scan (well-known or top ports), "
            "then service detection, then OS fingerprint. Full perimeter test. You decide the steps and approach."
            + _INTENT_SCHEMA
        ),
        "achieved_when": "full",
    },
]

def is_port_scan_goal(goal_id: Optional[str]) -> bool:
    """True if this goal skips host_reachability (well_known_tcp, full_stealth_tcp)."""
    return goal_id in PORT_SCAN_GOAL_IDS


def get_goal_text_by_id(goal_id: str) -> Optional[str]:
    """Return goal text for a given goal id, or None if unknown."""
    for g in GOALS:
        if g["id"] == goal_id:
            return g["text"]
    return None


def get_goal_label(goal_id: Optional[str]) -> str:
    """Return human-readable label for goal id, or the id itself if unknown/None."""
    if not goal_id:
        return "default"
    for g in GOALS:
        if g["id"] == goal_id:
            return g["label"]
    return goal_id


def list_goals() -> List[dict]:
    """Return list of {id, label, description} for UI dropdown and goal help."""
    return [
        {"id": g["id"], "label": g["label"], "description": g.get("description") or ""}
        for g in GOALS
    ]


# Default if no goal selected (use first fixed goal).
DEFAULT_GOAL_TEXT = GOALS[0]["text"]


def goal_achieved(state: ScanState, goal_id: Optional[str] = None) -> bool:
    """
    True when the current goal is achieved (scan can stop).
    goal_id: when set, use that goal's achieved_when; else use "full".
    For port_scan_only we do not stop on no_response until we've run at least one port_scan
    (ping may be blocked while ports are open).
    """
    achieved_when = "full"
    if goal_id:
        for g in GOALS:
            if g["id"] == goal_id:
                achieved_when = g.get("achieved_when") or "full"
                break
    # port_scan_only: one port_scan run is enough (host may be unknown if we skipped host_reachability).
    if achieved_when == "port_scan_only" and "port_scan" in state.scans_run:
        return True
    # port_scan_and_services: port_scan + (service_detect or service_detect_common) required.
    if achieved_when == "port_scan_and_services":
        port_done = "port_scan" in state.scans_run
        services_done = "service_detect" in state.scans_run or "service_detect_common" in state.scans_run
        if port_done and services_done:
            return True
        if state.host_reachability == "no_response":
            return False  # still allow port_scan then service_detect when ping blocked
    if state.host_reachability == "no_response":
        if achieved_when == "port_scan_only":
            return "port_scan" in state.scans_run  # try port scan even when ping blocked
        if achieved_when == "port_scan_and_services":
            return False
        return True
    # Port-scan goals do not run host_reachability; host may stay unknown. Do not require host == "up".
    if state.host_reachability != "up" and not is_port_scan_goal(goal_id):
        return False
    if achieved_when == "port_scan_only":
        return "port_scan" in state.scans_run
    if achieved_when == "port_scan_and_services":
        port_done = "port_scan" in state.scans_run
        services_done = "service_detect" in state.scans_run or "service_detect_common" in state.scans_run
        return bool(port_done and services_done)
    services_done = "service_detect" in state.scans_run or "service_detect_common" in state.scans_run
    os_done = state.os_fingerprint_done
    return bool(services_done and os_done)

"""
Validate API target and AI intents. Truly agentic: AI proposes intent + params; we validate and map to action_id.
Implementation design §5, §10.
"""
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from action_menu import intent_to_action_id
from scan_state import ScanState

# Single host or IP: hostname (alphanumeric, dots, hyphens) or IPv4. No lists, ranges, shell metacharacters.
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$", re.ASCII)
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", re.ASCII)


def validate_target(target: str) -> Optional[str]:
    """
    Validate target for API. Return normalized target string or None if invalid.
    No lists, no ranges, no shell metacharacters.
    """
    if not target or not isinstance(target, str):
        return None
    t = target.strip()
    if not t:
        return None
    if any(c in t for c in " \t\n;|&$`<>()[]{}'\"\\"):
        return None
    if _IPV4_RE.match(t):
        parts = t.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return t
        return None
    if _HOSTNAME_RE.match(t):
        return t
    return None


def _extract_json_object(text: str) -> Optional[str]:
    """Find the first complete {...} in text (respecting strings); return that substring or None."""
    text = (text or "").strip()
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape = False
    quote = None
    i = start
    while i < len(text):
        c = text[i]
        if escape:
            escape = False
            i += 1
            continue
        if in_string:
            if c == "\\":
                escape = True
            elif c == quote:
                in_string = False
            i += 1
            continue
        if c in ("'", '"'):
            in_string = True
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        i += 1
    return None


def _parse_json_candidate(text: str) -> Optional[dict]:
    """Try to parse text as JSON; return dict or None."""
    if not text or not text.strip():
        return None
    text = text.strip()
    # Remove markdown code fence: ```json ... ``` or ``` ... ```
    fence = re.match(r"^```(?:json)?\s*\n?(.*?)\n?```\s*$", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _norm_str(val: object) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, str):
        return val.strip() or None
    return str(val).strip() or None


def _norm_params(data: dict) -> Dict[str, Any]:
    """Extract intent params (range, scope) from data.
    Validation: use logs/runlogs/llm_log.txt. Log shows Goal (e.g. well-known TCP port scan) and schema
    (for port_scan \"range\" e.g. \"1-1024\"). If only 'nmap -sn ...' appears under Executed command
    and LLM responses show \"intent\": \"port_scan\", \"params\": {\"range\": \"1-1024\"}, then we were
    rejecting valid replies — LLM uses nested \"params\"; we must read data['params'], not top-level.
    """
    params: Dict[str, Any] = {}
    # Prefer nested data["params"] (actual LLM response shape).
    p = data.get("params")
    if isinstance(p, dict):
        for key in ("range", "port_range", "scope"):
            if p.get(key) is not None:
                params[key] = _norm_str(p[key])
    # Fallback: top-level keys
    if data.get("range") is not None and "range" not in params:
        params["range"] = _norm_str(data["range"])
    if data.get("port_range") is not None and "port_range" not in params:
        params["port_range"] = _norm_str(data["port_range"])
    if data.get("scope") is not None and "scope" not in params:
        params["scope"] = _norm_str(data["scope"])
    return params


def validate_intent(
    reply: str, state: ScanState, goal_id: Optional[str] = None
) -> Optional[Tuple[str, Optional[str], Optional[str], Optional[str], str, Dict[str, Any]]]:
    """
    Parse reply as intent + params; validate against state; map to action_id.
    goal_id: used for per-goal completion (e.g. full_stealth_tcp can be done after port_scan only).
    Returns (action_id, reason, reasoning, plan, intent, params) or None if invalid.
    """
    raw = (reply or "").strip()
    if not raw:
        return None

    data = _parse_json_candidate(raw)
    if data is None and "\n" in raw:
        data = _parse_json_candidate(raw.split("\n", 1)[0].strip())
    if data is None:
        extracted = _extract_json_object(raw)
        if extracted:
            try:
                data = json.loads(extracted)
            except json.JSONDecodeError:
                pass
    if data is None or not isinstance(data, dict):
        return None

    intent = _norm_str(data.get("intent"))
    if not intent:
        return None
    params = _norm_params(data)
    action_id = intent_to_action_id(intent, params, state, goal_id)
    if action_id is None:
        return None
    reason = _norm_str(data.get("reason"))
    reasoning = _norm_str(data.get("reasoning"))
    plan = _norm_str(data.get("plan"))
    return (action_id, reason, reasoning, plan, intent, params)

"""
Validate LLM reply: JSON with action_id in current menu. Validate API target. Implementation design §5, §10.
"""
import json
import re
from typing import List, Optional, Tuple

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


def validate_reply(reply: str, current_menu: List[str]) -> Optional[Tuple[str, Optional[str]]]:
    """
    Parse reply and validate. Return (action_id, reason) or None if reject.
    """
    line = (reply or "").strip()
    if not line:
        return None
    if "\n" in line:
        line = line.split("\n", 1)[0].strip()
    # Remove markdown code fence: ```json ... ``` or ``` ... ```
    fence = re.match(r"^```(?:json)?\s*\n?(.*?)\n?```\s*$", line, re.DOTALL)
    if fence:
        line = fence.group(1).strip()
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    action_id = data.get("action_id")
    if action_id is None or not isinstance(action_id, str):
        return None
    action_id = action_id.strip()
    if action_id not in current_menu:
        return None
    reason = data.get("reason")
    if reason is not None and not isinstance(reason, str):
        reason = str(reason)
    return (action_id, reason)

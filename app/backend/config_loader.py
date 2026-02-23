"""
Load scan_config.yaml (or scan_profile.yaml). Single source for target, LLM, and guardrails.
Implementation design §2, §10.
"""
from pathlib import Path
from typing import Any, Optional

import yaml

_BACKEND_ROOT = Path(__file__).resolve().parent
CONFIG_DIR = _BACKEND_ROOT / "config"
_CONFIG: Optional[dict] = None


def _load_config() -> dict:
    global _CONFIG
    if _CONFIG is not None:
        return _CONFIG
    for name in ("scan_config.yaml", "scan_profile.yaml"):
        path = CONFIG_DIR / name
        if path.exists():
            with open(path, encoding="utf-8-sig") as f:
                _CONFIG = yaml.safe_load(f) or {}
            return _CONFIG
    raise FileNotFoundError(f"No scan_config.yaml or scan_profile.yaml in {CONFIG_DIR}")


def _get(key_path: str, default: Any = None) -> Any:
    cfg = _load_config()
    keys = key_path.split(".")
    v = cfg
    for k in keys:
        v = v.get(k) if isinstance(v, dict) else None
        if v is None:
            return default
    return v


def get_scan_target() -> str:
    target = _get("target")
    if target and isinstance(target, str):
        return target.strip()
    target_key = _get("target_key")
    if target_key is not None:
        targets_path = CONFIG_DIR / "targets.yaml"
        if targets_path.exists():
            with open(targets_path, encoding="utf-8-sig") as f:
                targets_data = yaml.safe_load(f) or {}
            if isinstance(targets_data, list):
                idx = int(target_key) if isinstance(target_key, int) else int(target_key)
                return str(targets_data[idx]).strip()
            if isinstance(targets_data, dict):
                return str(targets_data.get(target_key, "")).strip()
    raise ValueError("Config: target or target_key required and must resolve to a non-empty string")


def get_run_nmap_sudo() -> bool:
    v = _get("run_nmap_sudo", True)
    return bool(v)


def get_nmap_execution() -> bool:
    if _get("dry_run", False):
        return False
    return bool(_get("nmap_execution", True))


def get_cooling() -> bool:
    return bool(_get("cooling", True))


def get_cooling_seconds() -> int:
    return int(_get("cooling_seconds", 4))


def get_max_steps() -> int:
    return int(_get("max_steps", 30))


def get_max_nmap_runs() -> int:
    return int(_get("max_nmap_runs", 25))


def get_max_elapsed_seconds() -> int:
    return int(_get("max_elapsed_seconds", 3600))


# Reject obvious placeholders so we fail fast instead of 401 in the loop.
_OPENAI_KEY_PLACEHOLDERS = ("your-key", "your-key)", "xxx", "sk-your-key", "paste-your-key-here")


def get_openai_api_key() -> str:
    path = _get("llm.openai_api_key_file", "config/openai.key.ignore")
    if not Path(path).is_absolute():
        path = _BACKEND_ROOT / path
    else:
        path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"API key file not found: {path}")
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if "=" in line:
                key = line.split("=", 1)[1].strip()
            else:
                key = line
            if not key or len(key) < 10:
                raise ValueError(
                    "OpenAI API key in config looks empty or too short. "
                    "Put your real key (sk-...) in config/openai.key.ignore. "
                    "Get it at https://platform.openai.com/account/api-keys"
                )
            if key.lower() in _OPENAI_KEY_PLACEHOLDERS or "your-key" in key.lower():
                raise ValueError(
                    "OpenAI API key looks like a placeholder (e.g. 'your-key'). "
                    "Put your real API key in config/openai.key.ignore. "
                    "Get it at https://platform.openai.com/account/api-keys"
                )
            if not key.startswith("sk-"):
                raise ValueError(
                    "OpenAI API key should start with 'sk-'. "
                    "Check config/openai.key.ignore. Get a key at https://platform.openai.com/account/api-keys"
                )
            return key
    raise ValueError(f"API key file empty: {path}")


def get_goal_text() -> str:
    return _get("goal_text") or "Find open ports, identify services and versions, and perform OS fingerprint on the target."

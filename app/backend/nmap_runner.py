"""
Run nmap via subprocess; argv from action_menu only. Implementation design §4, §6, §8, §10.
"""
import shutil
import subprocess
from typing import Tuple

from action_menu import get_nmap_argv


def run_nmap(
    target: str,
    action_id: str,
    use_sudo: bool,
    timeout_sec: int = 300,
) -> Tuple[str, str, int]:
    """
    Build argv from action_id mapping, run nmap, return (raw_command, xml_stdout, returncode).
    Never add --script, -sC, -A, -iL, -iR.
    """
    argv = get_nmap_argv(action_id, target, use_sudo, timeout_sec)
    if argv is None:
        return ("", "", 0)
    raw_command = " ".join(argv)
    run_timeout = timeout_sec + 60
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=run_timeout,
            shell=False,
        )
        return (raw_command, result.stdout or "", result.returncode)
    except subprocess.TimeoutExpired:
        return (raw_command, "", 1)
    except Exception:
        return (raw_command, "", 1)


def check_nmap_on_path() -> bool:
    return shutil.which("nmap") is not None


def check_sudo_nopasswd() -> bool:
    """Run sudo -n true; return True if success."""
    try:
        r = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5, shell=False)
        return r.returncode == 0
    except Exception:
        return False

"""
Run nmap via subprocess; argv from action_menu only. Implementation design §4, §6, §8, §10.
"""
import os
import shutil
import subprocess
import threading
from typing import Callable, List, Optional, Tuple

from action_menu import get_nmap_argv


def run_nmap(
    target: str,
    action_id: str,
    use_sudo: bool,
    timeout_sec: int = 300,
    open_ports: Optional[List[Tuple[int, str]]] = None,
    port_range: Optional[str] = None,
    output_stream_callback: Optional[Callable[[str], None]] = None,
) -> Tuple[str, str, int, str]:
    """
    Build argv from action_id mapping, run nmap, return (raw_command, xml_stdout, returncode, raw_stderr).
    xml_stdout is used only for internal parsing; raw_stderr is the human-readable nmap output for display.
    open_ports: for service_detect, only these ports are probed (when set).
    port_range: for action_id port_scan, the -p argument (e.g. '1-1024').
    output_stream_callback: if set, nmap stderr is streamed line-by-line to this callback and accumulated as raw_stderr.
    """
    argv = get_nmap_argv(action_id, target, use_sudo, timeout_sec, open_ports=open_ports, port_range=port_range)
    if argv is None:
        return ("", "", 0, "")
    raw_command = " ".join(argv)
    run_timeout = timeout_sec + 60

    if output_stream_callback is None:
        try:
            result = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=run_timeout,
                shell=False,
            )
            return (raw_command, result.stdout or "", result.returncode, result.stderr or "")
        except subprocess.TimeoutExpired:
            return (raw_command, "", 1, "")
        except Exception:
            return (raw_command, "", 1, "")

    # Stream stderr so we get output during run. Use PTY so nmap sees a TTY and line-buffers.
    # Do NOT prepend stdbuf when using sudo: sudo would run stdbuf instead of nmap, and sudoers
    # only allows NOPASSWD: /usr/bin/nmap, so "sudo -n stdbuf ... nmap" would ask for a password.
    stdbuf = shutil.which("stdbuf")
    if stdbuf and argv[0] != "sudo":
        argv = [stdbuf, "-e0", "-o0"] + argv

    use_pty = False
    try:
        import pty  # noqa: PLC0415
        use_pty = True
    except ImportError:
        pass

    if use_pty:
        return _run_nmap_stream_pty(argv, raw_command, run_timeout, output_stream_callback)
    return _run_nmap_stream_pipe(
        argv, run_timeout, output_stream_callback, raw_command=raw_command
    )


def _run_nmap_stream_pipe(
    argv: List[str],
    run_timeout: int,
    output_stream_callback: Callable[[str], None],
    raw_command: str,
) -> Tuple[str, str, int, str]:
    """Stream stderr via pipe; accumulate raw stderr for display. Return (raw_command, stdout, returncode, raw_stderr)."""
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            bufsize=1,
            start_new_session=True,  # no controlling terminal: child can't mess with shell on Ctrl+C
        )
        stdout_chunks: List[str] = []
        stderr_chunks: List[str] = []

        def read_stdout() -> None:
            if proc.stdout:
                while True:
                    chunk = proc.stdout.read(65536)
                    if not chunk:
                        break
                    stdout_chunks.append(chunk)

        def read_stderr() -> None:
            if proc.stderr:
                for line in iter(proc.stderr.readline, ""):
                    stderr_chunks.append(line)
                    output_stream_callback(line)

        t1 = threading.Thread(target=read_stdout, daemon=True)
        t2 = threading.Thread(target=read_stderr, daemon=True)
        t1.start()
        t2.start()
        proc.wait(timeout=run_timeout)
        # Drain stdout fully (XML); nmap may buffer until exit so allow time for reader to finish.
        t1.join(timeout=10)
        t2.join(timeout=5)
        if proc.returncode is None:
            proc.kill()
            proc.wait()
        return (raw_command, "".join(stdout_chunks), proc.returncode or 0, "".join(stderr_chunks))
    except subprocess.TimeoutExpired:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        return (raw_command, "", 1, "")
    except Exception:
        return (raw_command, "", 1, "")


def _run_nmap_stream_pty(
    argv: List[str],
    raw_command: str,
    run_timeout: int,
    output_stream_callback: Callable[[str], None],
) -> Tuple[str, str, int, str]:
    """Run nmap with stderr connected to a PTY; accumulate raw stderr for display. Return (raw_command, stdout, returncode, raw_stderr)."""
    import pty as pty_mod  # noqa: PLC0415

    master_fd, slave_fd = pty_mod.openpty()
    stderr_chunks: List[str] = []
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=slave_fd,
            text=False,
            shell=False,
            start_new_session=True,  # no controlling terminal: child can't mess with shell on Ctrl+C
        )
        os.close(slave_fd)
        slave_fd = -1
        stdout_chunks: List[bytes] = []
        stderr_buf = bytearray()

        def read_stdout() -> None:
            if proc.stdout:
                while True:
                    chunk = proc.stdout.read(65536)
                    if not chunk:
                        break
                    stdout_chunks.append(chunk)

        def read_stderr_pty() -> None:
            nonlocal stderr_buf
            while True:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                stderr_buf.extend(data)
                while True:
                    idx = stderr_buf.find(b"\n")
                    if idx < 0:
                        break
                    line = bytes(stderr_buf[: idx + 1]).decode("utf-8", errors="replace")
                    del stderr_buf[: idx + 1]
                    stderr_chunks.append(line)
                    output_stream_callback(line)
            if stderr_buf:
                s = stderr_buf.decode("utf-8", errors="replace")
                stderr_buf.clear()
                stderr_chunks.append(s)
                output_stream_callback(s)

        t1 = threading.Thread(target=read_stdout, daemon=True)
        t2 = threading.Thread(target=read_stderr_pty, daemon=True)
        t1.start()
        t2.start()
        proc.wait(timeout=run_timeout)
        try:
            os.close(master_fd)
        except OSError:
            pass
        master_fd = -1
        # Drain stdout fully (XML); nmap may buffer until exit so allow time for reader to finish.
        t1.join(timeout=10)
        t2.join(timeout=5)
        if proc.returncode is None:
            proc.kill()
            proc.wait()
        return (raw_command, b"".join(stdout_chunks).decode("utf-8", errors="replace"), proc.returncode or 0, "".join(stderr_chunks))
    except subprocess.TimeoutExpired:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if master_fd >= 0:
            try:
                os.close(master_fd)
            except OSError:
                pass
        return (raw_command, "", 1, "")
    except Exception:
        if slave_fd >= 0:
            try:
                os.close(slave_fd)
            except OSError:
                pass
        if master_fd >= 0:
            try:
                os.close(master_fd)
            except OSError:
                pass
        return (raw_command, "", 1, "")
    finally:
        if slave_fd >= 0:
            try:
                os.close(slave_fd)
            except OSError:
                pass
        if master_fd >= 0:
            try:
                os.close(master_fd)
            except OSError:
                pass


def check_nmap_on_path() -> bool:
    return shutil.which("nmap") is not None


def check_sudo_nopasswd() -> bool:
    """Check passwordless sudo for nmap (matches sudoers NOPASSWD for /usr/bin/nmap)."""
    nmap_path = shutil.which("nmap") or "/usr/bin/nmap"
    try:
        r = subprocess.run(
            ["sudo", "-n", nmap_path, "--version"],
            capture_output=True,
            timeout=10,
            shell=False,
        )
        return r.returncode == 0
    except Exception:
        return False

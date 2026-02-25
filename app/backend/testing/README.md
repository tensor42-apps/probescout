# Backend testing

## Run all three goals via API

With the backend already running (e.g. `./startup_backend.sh` on port 12001):

```bash
cd /path/to/backend
python3 testing/run_three_goals_via_api.py
```

This will:

1. POST `/api/scan` with `target=scanme.nmap.org` and `goal=simple_recon`, poll until status is `done` or `error`.
2. Same for `well_known_tcp` and `full_stealth_tcp`.
3. After each run, copy the current `logs/runlogs/report.txt` and `llm_log.txt` into `testing/run_result_<goal>.txt`.

Check `logs/runlogs/report.txt` and `llm_log.txt` for the last run, and `testing/run_result_*.txt` for per-goal snapshots.

## Environment note

If the report shows **"sudo: a password is required"** in the Output section, passwordless sudo for nmap is not configured on the machine. The backend still completes (LLM gets empty open ports and may reply `done`). To fix: see `docs/SUDO.md` and add e.g. `youruser ALL=(ALL) NOPASSWD: /usr/bin/nmap` in `/etc/sudoers.d/probescout`.

## full_stealth_tcp (port_scan_only)

For the **full_stealth_tcp** goal we stop as soon as at least one **port_scan** has run (no host_reachability or OS/service required). If the host was never probed, `host_reachability` stays `unknown`; the agent now treats the goal as achieved after one port_scan so it does not keep retrying.

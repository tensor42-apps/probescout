#!/usr/bin/env bash
# Start the backend RestAPI server (Python).
# Port: 12001 (see port_registry.yaml / port_table.md).
# Usage: from dev/app/ run ./backend/startup_backend.sh
# Implementation: start FastAPI/Flask app; see implementation_design.md.
#
# Run as normal user (do not use sudo). For SYN scan, set run_nmap_sudo: true
# in config/scan_config.yaml and allow passwordless sudo for nmap only (see config comments).
set -e
clear

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
PORT="${PROBESCOUT_BACKEND_PORT:-12001}"
if [ -d .venv ]; then
  source .venv/bin/activate
fi
exec uvicorn app:app --reload --port "$PORT"

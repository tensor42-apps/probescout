#!/usr/bin/env bash
# Create .venv and install backend dependencies. Run from backend directory.
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
echo "Creating venv in $SCRIPT_DIR/.venv ..."
python3 -m venv .venv
echo "Installing requirements ..."
.venv/bin/python3 -m pip install -r requirements.txt
echo "Done. Activate with: source .venv/bin/activate"
echo "Or run: .venv/bin/python3 -m uvicorn app:app --reload --port 12001"

#!/usr/bin/env bash
# Start the frontend dev server (Node.js).
# Usage: from dev/ run ./frontend/startup_frontend.sh
# Frontend port: 12000. Backend API: 12001 (or set VITE_API_ORIGIN for backend URL).
set -e
clear
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
if [ ! -d node_modules ]; then
  npm install
fi
npm run dev

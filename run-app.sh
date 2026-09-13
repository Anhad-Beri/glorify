#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "[1/2] Steel backend on :8010 (internal API)"
pkill -f "webapp/server.py" 2>/dev/null || true; sleep 1
PORT=8010 nohup python3 webapp/server.py > webapp/server.log 2>&1 &

echo "[2/2] Dashboard front door on :8000"
pkill -f "dashboard/server.mjs" 2>/dev/null || true; sleep 1
BACKEND_URL=http://127.0.0.1:8010 nohup node dashboard/server.mjs > dashboard/dashboard.log 2>&1 &
sleep 2
echo
echo "=================================================================="
echo "  Open:  http://127.0.0.1:8000"
echo "  Sign in: demo@glorify.local / glorify-demo"
echo "=================================================================="

#!/usr/bin/env bash
# Entry point for the Railway container. Not used for local dev — see run-app.sh for that.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="/root/.steel/bin:$PATH"

# --- Persist runtime state on the attached Railway Volume, if one is mounted ---
# Railway sets RAILWAY_VOLUME_MOUNT_PATH automatically once a volume is attached
# to this service. Falls back to a throwaway /data dir (ephemeral) if none is
# attached yet, so the app still boots.
DATA_DIR="${RAILWAY_VOLUME_MOUNT_PATH:-/data}"
mkdir -p "$DATA_DIR/reports" "$DATA_DIR/crawl_out"

ln -sfn "$DATA_DIR/.verified.json" .verified.json
ln -sfn "$DATA_DIR/.user_token" .user_token
ln -sfn "$DATA_DIR/history.json" webapp/history.json
rm -rf webapp/reports && ln -sfn "$DATA_DIR/reports" webapp/reports
rm -rf webapp/crawl_out && ln -sfn "$DATA_DIR/crawl_out" webapp/crawl_out

echo "[1/2] backend on :8010 (internal only)"
PORT=8010 nohup python3 webapp/server.py > webapp/server.log 2>&1 &

echo "[2/2] dashboard on Railway's public \$PORT (${PORT:-8000})"
DASHBOARD_HOST=0.0.0.0 DASHBOARD_PORT="${PORT:-8000}" BACKEND_URL=http://127.0.0.1:8010 \
  exec node dashboard/server.mjs

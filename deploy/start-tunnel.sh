#!/usr/bin/env bash
set -euo pipefail
ROOT="/Users/jaiteshgill/Desktop/Glorify/steel-pentest-agent"
cd "$ROOT/deploy"
pkill -f "cloudflared tunnel" 2>/dev/null || true; sleep 2
nohup cloudflared tunnel --url http://localhost:8080 > tunnel.log 2>&1 &
echo "cloudflared restarted (pid $!). waiting for URL..."
URL=""
for i in $(seq 1 30); do
  URL=$(grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' tunnel.log | head -1)
  [ -n "$URL" ] && break; sleep 2
done
[ -z "$URL" ] && { echo "no URL yet; see deploy/tunnel.log"; tail -15 tunnel.log; exit 1; }
echo "$URL" > .tunnel_url
python3 - "$URL" <<'PY'
import json, sys, urllib.parse
vf = "/Users/jaiteshgill/Desktop/Glorify/steel-pentest-agent/.verified.json"
p = urllib.parse.urlparse(sys.argv[1]); origin = f"{p.scheme}://{p.netloc}"
try: s = set(json.load(open(vf)))
except Exception: s = set()
s.add(origin); json.dump(sorted(s), open(vf, "w"))
print("auto-verified:", origin)
PY
echo
echo "==================================================================="
echo " PUBLIC URL (paste into the UI, NO token needed): $URL"
echo "==================================================================="

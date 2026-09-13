#!/usr/bin/env bash
set -euo pipefail

TOKEN="steel-verify-8a602f7bdff81cb8acd9c145042034b9"
APP_DIR="/opt/juice-target"

echo "[1/5] Installing Docker (if missing)..."
command -v docker >/dev/null 2>&1 || curl -fsSL https://get.docker.com | sh

echo "[2/5] Detecting public IP..."
IP="$(curl -fsS4 https://ifconfig.me 2>/dev/null || curl -fsS4 https://api.ipify.org)"
HOST="${IP//./-}.sslip.io"
echo "     public IP: $IP"
echo "     hostname : $HOST"

echo "[3/5] Writing deploy files to $APP_DIR ..."
mkdir -p "$APP_DIR"
cat > "$APP_DIR/docker-compose.yml" <<'YAML'
services:
  juice-shop:
    image: bkimminich/juice-shop
    restart: unless-stopped
    expose:
      - "3000"
  caddy:
    image: caddy:2
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - juice-shop
volumes:
  caddy_data:
  caddy_config:
YAML

cat > "$APP_DIR/Caddyfile" <<CADDY
${HOST} {
	handle /.well-known/steel-pentest-verify.txt {
		respond "${TOKEN}" 200
	}
	reverse_proxy juice-shop:3000
}
CADDY

echo "[4/5] Opening firewall (if ufw is active)..."
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 80/tcp || true; ufw allow 443/tcp || true
fi

echo "[5/5] Starting containers..."
cd "$APP_DIR"
docker compose up -d

echo
echo "=================================================================="
echo " Deploying. Give Caddy ~30s to fetch a Let's Encrypt certificate."
echo
echo "   PUBLIC URL : https://${HOST}"
echo "   TOKEN FILE : https://${HOST}/.well-known/steel-pentest-verify.txt"
echo
echo " Paste the PUBLIC URL into the agent UI -> Verify -> Full + active."
echo "=================================================================="

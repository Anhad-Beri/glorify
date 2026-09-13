#!/usr/bin/env bash
set -uo pipefail
export PATH="$HOME/.steel/bin:$PATH"
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a

sx() {
  local out rc
  out=$(steel computer exec --timeout "${2:-600}" -- sh -c "$1" 2>&1)
  rc=$?
  echo "$out" | python3 -c "import sys,json;
try:
    d=json.load(sys.stdin); print(d['data']['output']); sys.exit(d['data']['exitCode'])
except SystemExit: raise
except Exception:
    print(sys.stdin.read() if False else '', end=''); print('''$out'''[:500])"
  return $?
}

push() {
  local b64 ls rs
  b64=$(base64 -i "$1" | tr -d '\n')
  steel computer exec --timeout 120 -- sh -c "mkdir -p \$(dirname '$2') && echo '$b64' | base64 -d > '$2'" >/dev/null 2>&1
  ls=$(shasum -a 256 "$1" | awk '{print $1}')
  rs=$(steel computer exec -- sha256sum "$2" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['output'].split()[0])")
  [ "$ls" = "$rs" ] && echo "  pushed $1" || { echo "  PUSH FAILED $1"; exit 1; }
}

echo "==> [1/11] Creating Steel Computer (8h timeout, idle-pause off)..."
steel computer create --timeout 28800 --idle-timeout 0 --wait --use --json \
  | python3 -c "import sys,json;d=json.load(sys.stdin)['data'];print('  id=%s status=%s'%(d['id'],d['status']))"

echo "==> [2/11] Base packages (JRE-headless, sqlmap, curl, unzip, git, pip — NO docker)..."
sx 'apt-get update -y >/dev/null 2>&1 && apt-get install -y --no-install-recommends ca-certificates default-jre-headless sqlmap curl unzip git python3-pip 2>&1 | tail -3 && update-ca-certificates 2>&1 | tail -1' 1200

echo "==> [3/11] Fix Java libjli.so via ldconfig..."
sx 'echo /usr/lib/jvm/java-21-openjdk-amd64/lib > /etc/ld.so.conf.d/openjdk21.conf && ldconfig && java -version 2>&1 | head -1' 120

echo "==> [4/11] OWASP ZAP 2.17.0..."
sx 'curl -fsL -o /opt/zap.tar.gz https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz && tar -xzf /opt/zap.tar.gz -C /opt && ln -sfn /opt/ZAP_2.17.0 /opt/zap && echo "zap ok: $(ls /opt/zap/zap.sh)"' 1200

echo "==> [5/11] Nuclei 3.11.1 + templates..."
sx 'curl -fsL -o /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip && unzip -o /tmp/nuclei.zip -d /usr/local/bin >/dev/null && chmod +x /usr/local/bin/nuclei && /usr/local/bin/nuclei -update-templates 2>&1 | tail -2' 900

echo "==> [6/11] Node 22..."
sx 'curl -fsL -o /opt/node.tar.gz https://nodejs.org/dist/v22.23.2/node-v22.23.2-linux-x64.tar.gz && tar -xzf /opt/node.tar.gz -C /opt && ln -sfn /opt/node-v22.23.2-linux-x64 /opt/node && ln -sf /opt/node/bin/node /usr/local/bin/node && ln -sf /opt/node/bin/npm /usr/local/bin/npm && echo "node $(node --version)"' 600

echo "==> [7/11] OWASP Juice Shop 20.2.0 (Node bundle)..."
sx 'curl -fsL -o /opt/juiceshop.tgz https://github.com/juice-shop/juice-shop/releases/download/v20.2.0/juice-shop-20.2.0_node22_linux_x64.tgz && mkdir -p /opt/juice-shop && tar -xzf /opt/juiceshop.tgz -C /opt/juice-shop --strip-components=1 && echo "juice-shop $(grep -m1 version /opt/juice-shop/package.json)"' 600

echo "==> [8/11] Python deps for the on-Computer orchestrator..."
sx 'pip3 install --break-system-packages -q requests python-dotenv reportlab 2>&1 | tail -1; echo pip-done' 300
sx 'python3 -c "from reportlab.lib.styles import getSampleStyleSheet; from reportlab.platypus import SimpleDocTemplate, Paragraph; import io; d=SimpleDocTemplate(io.BytesIO()); d.build([Paragraph(chr(119)+chr(97)+chr(114)+chr(109), getSampleStyleSheet()[chr(78)+chr(111)+chr(114)+chr(109)+chr(97)+chr(108)])]); print(chr(114)+chr(108)+chr(45)+chr(119)+chr(97)+chr(114)+chr(109)+chr(101)+chr(100))"' 300

echo "==> [9/11] Push agent code..."
push checks_http.py       /root/agent/checks_http.py
push zap_client.py        /root/agent/zap_client.py
push report.py            /root/agent/report.py
push orchestrator_computer.py /root/agent/orchestrator.py
steel computer exec -- sh -c 'cat > /root/agent/.env <<EOF
TARGET_URL=http://localhost:3000
ZAP_API=http://localhost:8080
NUCLEI_BIN=/usr/local/bin/nuclei
SQLMAP_BIN=/usr/bin/sqlmap
RUN_ZAP=1
RUN_NUCLEI=1
RUN_SQLMAP=1
EOF
echo env-written' >/dev/null 2>&1
echo "  agent code + .env in place"

echo "==> [10/11] Launch ZAP (supervised, capped heap, no self-shutdown) + Juice Shop supervisor..."
sx 'rm -f /opt/zap/plugin/insights-alpha-*.zap; nohup sh -c "while true; do /opt/zap/zap.sh -daemon -host 0.0.0.0 -port 8080 -Xmx1024m -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.disablekey=true >> /var/log/zap.log 2>&1; echo ZAP-RESTART >> /var/log/zap.log; sleep 3; done" >/dev/null 2>&1 & echo zap-supervisor-launched' 60
sx 'cd /opt/juice-shop && nohup sh -c "while true; do node build/app.js >> /var/log/juiceshop.log 2>&1; echo restart >> /var/log/juiceshop.log; sleep 2; done" >/dev/null 2>&1 & echo juiceshop-supervisor-launched' 60

echo "==> [11/11] Wait for services..."
sx 'for i in $(seq 1 45); do
  J=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://localhost:3000/ 2>/dev/null)
  Z=$(curl -s --max-time 3 http://localhost:8080/JSON/core/view/version/ 2>/dev/null)
  if [ "$J" = "200" ] && echo "$Z" | grep -q version; then echo "READY: JuiceShop=$J ZAP=$Z"; break; fi
  sleep 3
done
curl -s -o /dev/null -w "Juice Shop -> %{http_code}\n" http://localhost:3000/
curl -s http://localhost:8080/JSON/core/view/version/' 200

echo ""
echo "==> Reprovision complete."

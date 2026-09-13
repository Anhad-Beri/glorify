# Glorify — Steel Computer Security Agent

An autonomous web-application pentesting agent. Enter a target you own and it runs real
security tools on a cloud Steel Computer (OWASP ZAP, Nuclei, sqlmap, plus custom HTTP
checks), has an LLM write the report narrative, and produces a PDF report mapped to the
OWASP Top 10. A target is only scanned if it is the exempt OWASP Juice Shop practice
instance or the user has proven ownership via a `/.well-known` token.

## Layout

```
report.py                 PDF builder (severity sort, OWASP coverage map)
checks_http.py            custom HTTP checks (IDOR, SQLi, weak-auth, clickjacking)
zap_client.py             OWASP ZAP REST client
orchestrator_computer.py  runs on the Steel Computer; drives the scanners over localhost
webapp/                   Python backend (server.py), crawler.py, writer.py, index.html
dashboard/                Node front door (auth + UI) that proxies to the backend
setup/reprovision.sh      one-command Steel Computer rebuild
deploy/                   self-hosted target (Juice Shop + Caddy + tunnel/VPS)
run-app.sh                starts the backend (:8010) + dashboard (:8000)
```

## Setup

```
cp .env.example .env         # set STEEL_API_KEY (and ANTHROPIC_API_KEY for narratives)
pip install -r requirements.txt
bash setup/reprovision.sh
```

## Run

```
bash run-app.sh
# open http://127.0.0.1:8000  (demo@glorify.local / glorify-demo)
# target http://localhost:3000 -> Full -> Run
```

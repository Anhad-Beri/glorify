import json
import os
import re
import secrets
import subprocess
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
HOST, PORT = "127.0.0.1", int(os.environ.get("PORT", "8000"))
AGENT_DIR = "/root/agent"
WELL_KNOWN_PATH = "/.well-known/steel-pentest-verify.txt"
VERIFIED_FILE = PROJECT / ".verified.json"

JUICE_SHOP = "http://localhost:3000"

_TARGET_RE = re.compile(
    r"^https?://"
    r"([a-zA-Z0-9.-]+)"
    r"(:\d{1,5})?"
    r"(/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?$"
)

def valid_target(url: str) -> bool:
    return bool(url) and len(url) < 2048 and bool(_TARGET_RE.match(url)) \
        and not any(c in url for c in "`$\\ \t\n\"'|;&<>")

def origin_of(url: str) -> str:
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def is_juice_shop(url: str) -> bool:
    return origin_of(url) == JUICE_SHOP

def _steel_env() -> dict:
    env = os.environ.copy()
    env["PATH"] = f"{Path.home()}/.steel/bin:" + env.get("PATH", "")
    if not env.get("STEEL_API_KEY"):
        dotenv = PROJECT / ".env"
        if dotenv.exists():
            for line in dotenv.read_text().splitlines():
                if line.startswith("STEEL_API_KEY="):
                    env["STEEL_API_KEY"] = line.split("=", 1)[1].strip()
    return env

def steel_exec(shell_cmd: str, timeout: int = 130) -> str:
    proc = subprocess.run(
        ["steel", "computer", "exec", "--timeout", str(timeout), "--", "sh", "-c", shell_cmd],
        capture_output=True, text=True, env=_steel_env(), timeout=timeout + 30,
    )
    try:
        return json.loads(proc.stdout)["data"]["output"]
    except Exception:
        return proc.stdout or proc.stderr

def _computer_gone(text: str) -> bool:
    t = (text or "").lower()
    return "computer not found" in t or '"error_code":"not_found"' in t or "not_found" in t

def _computer_alive() -> bool:
    try:
        proc = subprocess.run(["steel", "computer", "list", "--json"],
                              capture_output=True, text=True, env=_steel_env(), timeout=20)
        comps = json.loads(proc.stdout).get("data", {}).get("computers", [])
        return any(c.get("status") == "running" for c in comps)
    except Exception:
        return False

LOCK = threading.Lock()

USER_TOKEN_FILE = PROJECT / ".user_token"

def _user_token() -> str:
    try:
        t = USER_TOKEN_FILE.read_text().strip()
        if t:
            return t
    except Exception:
        pass
    t = "steel-verify-" + secrets.token_hex(16)
    try:
        USER_TOKEN_FILE.write_text(t)
    except Exception:
        pass
    return t

USER_TOKEN = _user_token()

def _load_verified() -> set[str]:
    try:
        return set(json.loads(VERIFIED_FILE.read_text()))
    except Exception:
        return set()

def _save_verified(s: set[str]):
    try:
        VERIFIED_FILE.write_text(json.dumps(sorted(s)))
    except Exception:
        pass

VERIFIED: set[str] = _load_verified()

def is_authorized(target: str) -> bool:
    return is_juice_shop(target) or origin_of(target) in _load_verified()

STATE = {
    "status": "idle", "log": "", "findings": [], "target": "",
    "report_ready": False, "error": "", "progress": {},
    "phase": "", "viewer_url": "", "run_id": "",
}

def _set(**kw):
    with LOCK:
        STATE.update(kw)

def _anthropic_creds() -> tuple[str | None, str | None]:
    env = _steel_env()
    key = env.get("ANTHROPIC_API_KEY")
    wsid = env.get("ANTHROPIC_WORKSPACE_ID")
    if not key and (PROJECT / ".env").exists():
        for line in (PROJECT / ".env").read_text().splitlines():
            if line.startswith("ANTHROPIC_API_KEY="):
                key = line.split("=", 1)[1].strip()
            elif line.startswith("ANTHROPIC_WORKSPACE_ID="):
                wsid = line.split("=", 1)[1].strip()
    return key, wsid

LOCAL_PDF = ROOT / "pentest_report.pdf"
REPORTS_DIR = ROOT / "reports"
HISTORY_FILE = ROOT / "history.json"

def _load_history() -> list[dict]:
    try:
        return json.loads(HISTORY_FILE.read_text())
    except Exception:
        return []

def _save_run_to_history(run_id: str, target: str, mode: str, active: bool,
                         findings: list[dict], log: str = "") -> None:
    import shutil
    REPORTS_DIR.mkdir(exist_ok=True)
    high = sum(1 for f in findings if str(f.get("severity", "")).lower().startswith("high"))
    pdf_name = ""
    try:
        if LOCAL_PDF.exists():
            shutil.copyfile(LOCAL_PDF, REPORTS_DIR / f"{run_id}.pdf")
            pdf_name = f"{run_id}.pdf"
    except Exception:
        pass
    rec = {
        "id": run_id, "target": target, "mode": mode, "active": active,
        "when": time.strftime("%Y-%m-%d %H:%M", time.localtime()),
        "total": len(findings), "high": high, "pdf": pdf_name,
        "log": [ln for ln in (log or "").split("\n") if ln.strip()][-20:],
        "findings": [{k: f.get(k) for k in ("severity", "category", "tool", "endpoint", "description")}
                     for f in findings],
    }
    hist = _load_history()
    hist.insert(0, rec)
    try:
        HISTORY_FILE.write_text(json.dumps(hist[:50], indent=2))
    except Exception:
        pass

def _assemble_report(target: str, findings: list[dict]) -> bool:
    import sys as _s
    for p in (str(PROJECT), str(ROOT)):
        if p not in _s.path:
            _s.path.insert(0, p)
    try:
        import report
        import writer
        pages, coverage = [], ""
        cj = ROOT / "crawl_out" / "crawl.json"
        if cj.exists():
            try:
                cd = json.loads(cj.read_text())
                if cd.get("target") == target:
                    coverage = cd.get("coverage_notes", "")
                    for p in cd.get("pages", []):
                        pages.append({"url": p.get("url"), "title": p.get("title"),
                                      "screenshot": str(ROOT / "crawl_out" / p.get("screenshot", ""))})
            except Exception:
                pass
        key, wsid = _anthropic_creds()
        narrative = writer.generate_narrative(findings, target, coverage, api_key=key, workspace_id=wsid)
        report.generate_report(findings, output_path=str(LOCAL_PDF), target=target,
                               narrative=narrative, pages=pages)
        return LOCAL_PDF.exists()
    except Exception as e:
        _set(log=STATE.get("log", "") + f"\nReport assembly failed: {type(e).__name__}: {e}")
        return False

def run_scan(target: str, mode: str, active: bool):
    run_id = "RUN-" + time.strftime("%m%d-%H%M%S")
    try:
        _set(status="running", log="", findings=[], report_ready=False, error="",
             target=target, progress={}, phase="", viewer_url="", run_id=run_id)

        is_local = urllib.parse.urlparse(target).hostname in ("localhost", "127.0.0.1")
        if not is_local:
            _set(phase="crawling", log="Crawling the target with a Steel Browser session…")
            try:
                import sys as _sys, base64 as _b64
                _sys.path.insert(0, str(ROOT))
                from crawler import crawl
                key = _steel_env().get("STEEL_API_KEY")
                out = str(ROOT / "crawl_out")
                cr = crawl(target, out_dir=out, api_key=key,
                           verified=not is_juice_shop(target), verification_method="well-known",
                           on_viewer=lambda u: _set(viewer_url=u),
                           max_pages=int(os.environ.get("MAX_PAGES", "8")))
                cj = Path(out) / "crawl.json"
                b = _b64.b64encode(cj.read_bytes()).decode()
                steel_exec(f"echo '{b}' | base64 -d > {AGENT_DIR}/crawl.json", timeout=60)
                _set(log=f"Crawl complete: {len(cr['pages'])} pages, "
                         f"{len(cr['endpoints'])} endpoints discovered. Handing off to scanners…")
            except Exception as e:
                _set(log=f"Crawl step skipped ({type(e).__name__}: {e}); scanning without it.")
                steel_exec(f"rm -f {AGENT_DIR}/crawl.json", timeout=30)
        else:
            steel_exec(f"rm -f {AGENT_DIR}/crawl.json", timeout=30)
        _set(phase="scanning")

        run_active = active or is_juice_shop(target)
        flags = [f'TARGET_URL="{target}"']
        flags.append("REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt")
        flags.append("JUICE_SHOP=1" if is_juice_shop(target) else "JUICE_SHOP=0")
        if mode == "fast":
            flags += ["SKIP_ZAP_SCAN=1", "RUN_NUCLEI=0", "RUN_SQLMAP=0"]
        else:
            flags += ["RUN_ZAP=1", "RUN_NUCLEI=1", f"RUN_SQLMAP={'1' if run_active else '0'}"]
        flags.append(f"ZAP_ACTIVE={'1' if run_active else '0'}")
        env = " ".join(flags)

        launch = (
            f"cd {AGENT_DIR} && rm -f run.log run.done pentest_report.pdf findings.json && "
            f"nohup sh -c '{env} python3 -u orchestrator.py > run.log 2>&1; "
            f"echo EXIT=$? > run.done' >/dev/null 2>&1 & sleep 1; echo launched"
        )
        launch_out = steel_exec(launch, timeout=60)
        if _computer_gone(launch_out):
            _set(status="error", error="Steel Computer is unavailable (it may have stopped — "
                                       "they expire after their lifetime). Recreate it with "
                                       "`bash setup/reprovision.sh`, then retry.")
            return

        deadline = time.time() + 1800
        finished = False
        while time.time() < deadline:
            out = steel_exec(
                f"cat {AGENT_DIR}/run.log 2>/dev/null; echo '<<<DONE>>>'; "
                f"cat {AGENT_DIR}/run.done 2>/dev/null; echo '<<<ZAP>>>'; "
                f"curl -s http://localhost:8080/JSON/spider/view/scans/; echo '<<<A>>>'; "
                f"curl -s http://localhost:8080/JSON/ascan/view/scans/; echo '<<<N>>>'; "
                f"curl -s http://localhost:8080/JSON/core/view/numberOfAlerts/",
                timeout=60,
            )
            if _computer_gone(out):
                _set(status="error", error="Steel Computer stopped mid-scan (lifetime reached). "
                                           "Recreate it with `bash setup/reprovision.sh`, then retry.")
                return
            log_part, _, rest = out.partition("<<<DONE>>>")
            done_part, _, zap_part = rest.partition("<<<ZAP>>>")
            _set(log=log_part.strip(), progress=_parse_zap_progress(zap_part))
            if "EXIT=" in done_part:
                finished = True
                break
            time.sleep(2)

        if not finished:
            _set(status="error", error="Scan timed out.")
            return

        fj = steel_exec(f"cat {AGENT_DIR}/findings.json 2>/dev/null", timeout=60)
        findings = []
        try:
            findings = json.loads(fj).get("findings", [])
        except Exception:
            pass
        _set(phase="reporting", log=STATE.get("log", "") + "\nAssembling the report on the Mac…")
        ok = _assemble_report(target, findings)
        if ok:
            _save_run_to_history(run_id, target, mode, active, findings, STATE.get("log", ""))
        _set(status="done", findings=findings, report_ready=ok, phase="", run_id=run_id)
    except Exception as e:
        _set(status="error", error=f"{type(e).__name__}: {e}")

def _parse_zap_progress(blob: str) -> dict:
    prog = {"spider": None, "ascan": None, "requests": None, "alerts": None}
    try:
        spider_s, _, rest = blob.partition("<<<A>>>")
        ascan_s, _, num_s = rest.partition("<<<N>>>")

        def last_scan(s):
            scans = json.loads(s.strip()).get("scans", [])
            return scans[-1] if scans else {}

        sp = last_scan(spider_s)
        if sp:
            prog["spider"] = int(sp.get("progress", 0))
        asc = last_scan(ascan_s)
        if asc:
            prog["ascan"] = int(asc.get("progress", 0))
            prog["requests"] = int(asc.get("reqCount", 0))
        prog["alerts"] = int(json.loads(num_s.strip()).get("numberOfAlerts", 0))
    except Exception:
        pass
    return prog

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return {}

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, (ROOT / "index.html").read_text(), "text/html; charset=utf-8")
        elif self.path == "/api/status":
            with LOCK:
                self._send(200, dict(STATE))
        elif self.path == "/api/token":
            with LOCK:
                self._send(200, {"token": USER_TOKEN, "well_known_path": WELL_KNOWN_PATH,
                                 "verified": sorted(_load_verified())})
        elif self.path == "/api/history":
            self._send(200, {"runs": _load_history()})
        elif self.path == "/api/health":
            self._send(200, {"backend": True, "computer": _computer_alive()})
        elif self.path.split("?")[0] == "/api/report":
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            run = (params.get("run") or [""])[0]
            pdf_path = None
            if run:
                cand = REPORTS_DIR / f"{run}.pdf"
                if cand.exists():
                    pdf_path = cand
            if pdf_path is None and LOCAL_PDF.exists():
                pdf_path = LOCAL_PDF
            if pdf_path:
                pdf = pdf_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition", "inline; filename=pentest_report.pdf")
                self.send_header("Content-Length", str(len(pdf)))
                self.end_headers()
                self.wfile.write(pdf)
            else:
                self._send(404, {"error": "report not available"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/api/verify/start":
            self._verify_start()
        elif self.path == "/api/verify/check":
            self._verify_check()
        elif self.path == "/api/scan":
            self._scan()
        else:
            self._send(404, {"error": "not found"})

    def _verify_start(self):
        target = (self._body().get("target") or "").strip()
        if not valid_target(target):
            self._send(400, {"error": "Enter a valid http(s) URL."})
            return
        if is_juice_shop(target):
            self._send(200, {"exempt": True,
                             "message": "OWASP Juice Shop is the exempt practice target — no verification needed."})
            return
        self._send(200, {
            "exempt": False, "token": USER_TOKEN,
            "url": origin_of(target) + WELL_KNOWN_PATH,
            "instructions": f"Host a file at {origin_of(target)}{WELL_KNOWN_PATH} "
                            f"containing exactly your token, then click Check. "
                            f"This token never changes — reuse it for every site you own.",
        })

    def _verify_check(self):
        target = (self._body().get("target") or "").strip()
        if not valid_target(target):
            self._send(400, {"error": "Enter a valid http(s) URL."})
            return
        origin = origin_of(target)
        try:
            r = requests.get(origin + WELL_KNOWN_PATH, timeout=10, allow_redirects=False)
            got = r.text.strip()
        except Exception as e:
            self._send(200, {"verified": False, "detail": f"Could not fetch the file: {e}"})
            return
        if r.status_code == 200 and USER_TOKEN in got:
            with LOCK:
                VERIFIED.add(origin)
                _save_verified(VERIFIED)
            self._send(200, {"verified": True,
                             "detail": f"Ownership of {origin} confirmed (remembered permanently)."})
        else:
            self._send(200, {"verified": False,
                             "detail": f"Token not found (HTTP {r.status_code}). File must contain: {USER_TOKEN}"})

    def _scan(self):
        body = self._body()
        target = (body.get("target") or "").strip()
        mode = body.get("mode", "fast")
        active = bool(body.get("active", False))
        affirm = bool(body.get("affirm", False))

        if not valid_target(target):
            self._send(400, {"error": "Enter a valid http(s) URL."})
            return
        if not affirm:
            self._send(403, {"error": "You must affirm you own or are authorized to test this target."})
            return
        if not is_authorized(target):
            self._send(403, {"error": f"'{origin_of(target)}' is not verified. Prove ownership via the "
                                      f"/.well-known token first (or use the exempt Juice Shop target)."})
            return
        with LOCK:
            if STATE["status"] == "running":
                self._send(409, {"error": "A scan is already running."})
                return
        threading.Thread(target=run_scan, args=(target, mode, active), daemon=True).start()
        self._send(200, {"started": True, "target": target,
                         "active": active or is_juice_shop(target)})

if __name__ == "__main__":
    print(f"Steel Pentest Agent UI -> http://{HOST}:{PORT}")
    print(f"Exempt target: {JUICE_SHOP} | Verified: {sorted(VERIFIED) or 'none'}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()

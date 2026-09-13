import os
import json
import subprocess

from dotenv import load_dotenv

from checks_http import check_idor, check_auth, check_sqli, check_clickjacking
from zap_client import spider_target, trigger_active_scan, get_zap_alerts, seed_urls
from report import generate_report

CRAWL_FILE = "crawl.json"

def load_crawl_endpoints() -> list[str]:
    if not os.path.exists(CRAWL_FILE):
        return []
    try:
        data = json.load(open(CRAWL_FILE))
        urls = [e.get("url") for e in data.get("endpoints", []) if e.get("url")]
        seen, out = set(), []
        for u in urls:
            if u not in seen:
                seen.add(u); out.append(u)
        return out
    except Exception:
        return []

load_dotenv()

TARGET_URL = os.environ.get("TARGET_URL", "http://localhost:3000")
ZAP_API = os.environ.get("ZAP_API", "http://localhost:8080")
NUCLEI_BIN = os.environ.get("NUCLEI_BIN", "nuclei")
SQLMAP_BIN = os.environ.get("SQLMAP_BIN", "sqlmap")
RUN_ZAP = os.environ.get("RUN_ZAP", "1") == "1"
SKIP_ZAP_SCAN = os.environ.get("SKIP_ZAP_SCAN", "0") == "1"
ZAP_ACTIVE = os.environ.get("ZAP_ACTIVE", "1") == "1"
JUICE_SHOP = os.environ.get("JUICE_SHOP", "1") == "1"
RUN_NUCLEI = os.environ.get("RUN_NUCLEI", "1") == "1"
RUN_SQLMAP = os.environ.get("RUN_SQLMAP", "1") == "1"

def run_browser_checks() -> list[dict]:
    findings: list[dict] = []
    checks = [("Clickjacking", lambda: check_clickjacking(TARGET_URL))]
    if JUICE_SHOP:
        checks = [
            ("IDOR", lambda: check_idor(TARGET_URL)),
            ("SQLi", lambda: check_sqli(TARGET_URL)),
            ("Auth", lambda: check_auth(TARGET_URL)),
        ] + checks
    else:
        print("  (external target: skipping Juice-Shop-specific PoCs; using generic tools)")
    for name, fn in checks:
        try:
            got = fn()
            print(f"  [check] {name}: {len(got)} finding(s)")
            findings += got
        except Exception as e:
            print(f"  [check] {name}: ERROR {type(e).__name__}: {e}")
    return findings

def run_nuclei(extra_urls: list[str] | None = None) -> list[dict]:
    cmd = [NUCLEI_BIN, "-jsonl", "-silent", "-u", TARGET_URL,
           "-severity", "critical,high,medium",
           "-concurrency", "50", "-rate-limit", "300",
           "-timeout", "5", "-retries", "1", "-no-interactsh"]
    if extra_urls:
        listfile = "/tmp/nuclei_targets.txt"
        with open(listfile, "w") as fh:
            fh.write("\n".join(extra_urls))
        cmd += ["-l", listfile]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        out = result.stdout
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        print("  [nuclei] hit 5-min cap; using partial results")
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append({
            "category": "A06: Vulnerable Components",
            "tool": "Nuclei",
            "severity": raw.get("info", {}).get("severity", "unknown").capitalize(),
            "description": raw.get("info", {}).get("name", "Unnamed Nuclei finding"),
            "endpoint": raw.get("matched-at", TARGET_URL),
            "evidence": raw.get("extracted-results", raw.get("matcher-name", "")),
        })
    return findings

def run_sqlmap() -> list[dict]:
    target = f"{TARGET_URL}/rest/user/login"
    cmd = [
        SQLMAP_BIN, "-u", target,
        "--data", '{"email":"test@test.com","password":"test"}',
        "--headers=Content-Type: application/json",
        "-p", "email", "--batch", "--dbms", "sqlite",
        "--level", "1", "--risk", "1", "--technique=BEUS",
        "--flush-session", "-v", "0",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        print("  [sqlmap] timed out")
        return []
    out = result.stdout
    confirmed = ("Parameter:" in out and "Type:" in out) or "is vulnerable" in out
    if confirmed:
        start = out.find("Parameter:")
        evidence = out[start:start + 600] if start != -1 else out[-600:]
        return [{
            "category": "A03: Injection (SQLi)",
            "tool": "sqlmap",
            "severity": "High",
            "description": "sqlmap confirmed a SQL injection point in the login 'email' "
                           "parameter — user input reaches the SQL query unsanitized.",
            "endpoint": target,
            "evidence": evidence.strip(),
        }]
    print("  [sqlmap] no injection confirmed")
    return []

def main():
    findings: list[dict] = []

    print(f"Target: {TARGET_URL}")
    crawl_endpoints = load_crawl_endpoints()
    if crawl_endpoints:
        print(f"Loaded {len(crawl_endpoints)} endpoint(s) from the browser crawl.")

    print("Running HTTP-based checks (IDOR / auth / clickjacking)...")
    findings += run_browser_checks()

    if RUN_ZAP:
        try:
            if SKIP_ZAP_SCAN:
                print("Reusing ZAP's existing alerts (skipping rescan)...")
            else:
                if crawl_endpoints:
                    n = seed_urls(ZAP_API, crawl_endpoints)
                    print(f"  seeded {n} crawl endpoint(s) into ZAP's sites tree")
                if ZAP_ACTIVE:
                    print("Triggering ZAP spider + ACTIVE scan (fires real payloads)...")
                    trigger_active_scan(ZAP_API, TARGET_URL)
                else:
                    print("Running ZAP spider + PASSIVE scan only (no attack payloads)...")
                    spider_target(ZAP_API, TARGET_URL)
            zap = get_zap_alerts(ZAP_API)
            print(f"  [ZAP] {len(zap)} alert(s)")
            findings += zap
        except Exception as e:
            print(f"  [ZAP] ERROR {type(e).__name__}: {e}")

    if RUN_NUCLEI:
        print("Running Nuclei...")
        try:
            nuc = run_nuclei(crawl_endpoints)
            print(f"  [Nuclei] {len(nuc)} finding(s)")
            findings += nuc
        except Exception as e:
            print(f"  [Nuclei] ERROR {type(e).__name__}: {e}")

    if RUN_SQLMAP:
        print("Running sqlmap against the login endpoint...")
        try:
            findings += run_sqlmap()
        except Exception as e:
            print(f"  [sqlmap] ERROR {type(e).__name__}: {e}")

    print(f"Generating report ({len(findings)} findings)...")
    generate_report(findings, output_path="pentest_report.pdf", target=TARGET_URL)
    with open("findings.json", "w") as fh:
        json.dump({"target": TARGET_URL, "count": len(findings), "findings": findings}, fh)
    print("Done — see pentest_report.pdf")

if __name__ == "__main__":
    main()

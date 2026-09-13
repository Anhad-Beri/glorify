import http from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { extname } from "node:path";
import { pathToFileURL } from "node:url";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 8000;

const BACKEND_URL = process.env.BACKEND_URL ?? "http://127.0.0.1:8010";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 16 * 1024;
const assets = new Map([
  ["/signin", readFileSync(new URL("./public/signin.html", import.meta.url))],
  ["/app", readFileSync(new URL("./public/app.html", import.meta.url))],
  ["/assets/styles.css", readFileSync(new URL("./public/styles.css", import.meta.url))],
  ["/assets/signin.js", readFileSync(new URL("./public/signin.js", import.meta.url))],
  ["/assets/app.js", readFileSync(new URL("./public/app.js", import.meta.url))],
  ["/assets/favicon.svg", readFileSync(new URL("./public/glorify-mark.svg", import.meta.url))],
  ["/assets/glorify-mark.svg", readFileSync(new URL("./public/glorify-mark.svg", import.meta.url))],
  ["/assets/glorify-logo-dark.svg", readFileSync(new URL("./public/glorify-logo-dark.svg", import.meta.url))],
  ["/assets/glorify-logo-light.svg", readFileSync(new URL("./public/glorify-logo-light.svg", import.meta.url))]
]);

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml; charset=utf-8"
};

function secureEqual(actual, expected) {
  const actualBytes = Buffer.from(actual);
  const expectedBytes = Buffer.from(expected);
  if (actualBytes.length !== expectedBytes.length) return false;
  return timingSafeEqual(actualBytes, expectedBytes);
}

function parseCookies(header = "") {
  return Object.fromEntries(header.split(";").map((part) => part.trim()).filter(Boolean).map((part) => {
    const separator = part.indexOf("=");
    return separator === -1 ? [part, ""] : [part.slice(0, separator), decodeURIComponent(part.slice(separator + 1))];
  }));
}

function securityHeaders(contentType) {
  return {
    "cache-control": "no-store",
    "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "content-type": contentType,
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY"
  };
}

function send(response, status, contentType, body, extraHeaders = {}) {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body);
  response.writeHead(status, { ...securityHeaders(contentType), "content-length": payload.length, ...extraHeaders });
  response.end(payload);
}

function sendJson(response, status, body, extraHeaders = {}) {
  send(response, status, "application/json; charset=utf-8", JSON.stringify(body), extraHeaders);
}

function redirect(response, location) {
  response.writeHead(303, { ...securityHeaders("text/plain; charset=utf-8"), location });
  response.end();
}

async function readJson(request) {
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new Error("Request body is too large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

function normalizeTarget(value) {
  const url = new URL(String(value));
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error("Target must use HTTP or HTTPS");
  return url.toString();
}

async function backendJson(path, options = {}) {
  const response = await fetch(`${BACKEND_URL}${path}`, {
    ...options,
    headers: { "content-type": "application/json", ...(options.headers ?? {}) }
  });
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  return { ok: response.ok, status: response.status, data };
}

function normalizeSeverity(value) {
  const s = String(value ?? "").toLowerCase();
  if (s.startsWith("high") || s === "critical") return "High";
  if (s.startsWith("med")) return "Medium";
  if (s.startsWith("low")) return "Low";
  return "Info";
}

export function createDashboardServer({
  email = process.env.GLORIFY_DEMO_EMAIL ?? "demo@glorify.local",
  password = process.env.GLORIFY_DEMO_PASSWORD ?? "glorify-demo"
} = {}) {
  const sessions = new Map();

  function getSession(request) {
    const token = parseCookies(request.headers.cookie).glorify_session;
    const session = token ? sessions.get(token) : undefined;
    if (!session) return undefined;
    if (session.expiresAt <= Date.now()) {
      sessions.delete(token);
      return undefined;
    }
    return { token, ...session };
  }

  return http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://dashboard.local");
    const session = getSession(request);

    try {
      if (request.method === "GET" && url.pathname === "/health") return sendJson(response, 200, { status: "ok", service: "glorify-dashboard" });
      if (request.method === "GET" && url.pathname === "/") return redirect(response, session ? "/app" : "/signin");
      if (request.method === "GET" && url.pathname === "/signin") return session ? redirect(response, "/app") : send(response, 200, contentTypes[".html"], assets.get("/signin"));
      if (request.method === "GET" && url.pathname === "/app") return session ? send(response, 200, contentTypes[".html"], assets.get("/app")) : redirect(response, "/signin");

      if (request.method === "GET" && assets.has(url.pathname)) {
        return send(response, 200, contentTypes[extname(url.pathname)] ?? "application/octet-stream", assets.get(url.pathname));
      }

      if (request.method === "POST" && url.pathname === "/api/signin") {
        const input = await readJson(request);
        if (!secureEqual(String(input.email ?? ""), email) || !secureEqual(String(input.password ?? ""), password)) {
          return sendJson(response, 401, { error: "Email or password is incorrect" });
        }
        const token = randomBytes(32).toString("base64url");
        sessions.set(token, { email, expiresAt: Date.now() + SESSION_TTL_MS, settings: { defaultMode: "full", browserVerification: true, screenshots: true, independentMarker: true, autoReport: true } });
        return sendJson(response, 200, { signedIn: true }, { "set-cookie": `glorify_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}` });
      }

      if (request.method === "POST" && url.pathname === "/api/signout") {
        if (session) sessions.delete(session.token);
        return sendJson(response, 200, { signedOut: true }, { "set-cookie": "glorify_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" });
      }

      if (url.pathname.startsWith("/api/") && !session) return sendJson(response, 401, { error: "Sign in required" });

      if (request.method === "GET" && url.pathname === "/api/dashboard") {

        const runs = [], reports = [];
        try {
          const hist = await backendJson("/api/history");
          for (const r of (hist.data?.runs ?? [])) {
            const modeLabel = r.mode === "fast" ? "Fast / reuse ZAP" : "Full scan";
            runs.push({
              id: r.id, target: r.target, mode: modeLabel,
              result: `Complete · ${r.total} findings`, status: "complete",
              when: r.when, duration: "—", session: "steel",
              phases: ["Steel Browser crawl", "ZAP · Nuclei · sqlmap", "Claude report assembly"],
              log: r.log ?? []
            });
            reports.push({
              run: r.id, target: r.target, mode: modeLabel,
              summary: `${r.total} findings · ${r.high} high severity`, generated: r.when,
              total: r.total, high: r.high, duration: "—",
              findings: (r.findings ?? []).slice(0, 80).map((f) => ({
                severity: normalizeSeverity(f.severity),
                title: f.category ?? f.tool ?? "Finding",
                evidence: f.tool ?? "tool",
                endpoint: f.endpoint ?? ""
              }))
            });
          }
        } catch {  }
        return sendJson(response, 200, { user: { email: session.email }, runs, reports, settings: session.settings });
      }

      if (request.method === "POST" && url.pathname === "/api/runs") {
        const input = await readJson(request);
        const target = normalizeTarget(input.target);
        if (!["fast", "full"].includes(input.mode)) return sendJson(response, 400, { error: "Choose a valid scan mode" });

        const launch = await backendJson("/api/scan", {
          method: "POST",
          body: JSON.stringify({ target, mode: input.mode, active: input.mode === "full", affirm: true })
        });
        if (!launch.ok) {
          return sendJson(response, launch.status || 502, { error: launch.data.error ?? "Backend refused the scan" });
        }
        return sendJson(response, 202, { id: `RUN-${String(Date.now()).slice(-4)}`, target, mode: input.mode, simulated: false, status: "running" });
      }

      if (request.method === "GET" && url.pathname === "/api/status") {
        const status = await backendJson("/api/status");
        return sendJson(response, status.ok ? 200 : 502, status.data);
      }

      if (request.method === "GET" && url.pathname === "/api/health") {
        const h = await backendJson("/api/health");
        return sendJson(response, h.ok ? 200 : 502, h.ok ? h.data : { backend: false, computer: false });
      }

      if (request.method === "GET" && url.pathname === "/api/token") {
        const t = await backendJson("/api/token");
        return sendJson(response, t.ok ? 200 : 502, t.data);
      }

      if (request.method === "POST" && url.pathname === "/api/verify/start") {
        const input = await readJson(request);
        const v = await backendJson("/api/verify/start", { method: "POST", body: JSON.stringify(input) });
        return sendJson(response, v.status || (v.ok ? 200 : 502), v.data);
      }

      if (request.method === "POST" && url.pathname === "/api/verify/check") {
        const input = await readJson(request);
        const v = await backendJson("/api/verify/check", { method: "POST", body: JSON.stringify(input) });
        return sendJson(response, v.status || (v.ok ? 200 : 502), v.data);
      }

      if (request.method === "GET" && url.pathname === "/api/report") {
        const r = await fetch(`${BACKEND_URL}/api/report${url.search || ""}`);
        if (!r.ok) return sendJson(response, 404, { error: "Report not available yet" });
        const buf = Buffer.from(await r.arrayBuffer());
        response.writeHead(200, { ...securityHeaders("application/pdf"), "content-length": buf.length, "content-disposition": "inline; filename=pentest_report.pdf" });
        return response.end(buf);
      }

      if (request.method === "POST" && url.pathname === "/api/settings") {
        const input = await readJson(request);
        session.settings = {
          defaultMode: input.defaultMode === "fast" ? "fast" : "full",
          browserVerification: Boolean(input.browserVerification),
          screenshots: Boolean(input.screenshots),
          independentMarker: Boolean(input.independentMarker),
          autoReport: Boolean(input.autoReport)
        };
        sessions.get(session.token).settings = session.settings;
        return sendJson(response, 200, { saved: true, settings: session.settings });
      }

      return sendJson(response, 404, { error: "Not found" });
    } catch (error) {
      const message = error instanceof SyntaxError ? "Invalid JSON" : error.message;
      return sendJson(response, 400, { error: message });
    }
  });
}

function isMainModule() {
  return process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMainModule()) {
  const host = process.env.DASHBOARD_HOST ?? DEFAULT_HOST;
  const port = Number(process.env.DASHBOARD_PORT ?? DEFAULT_PORT);
  createDashboardServer().listen(port, host, () => {
    console.log(`Glorify dashboard: http://${host}:${port}`);
    if (!process.env.GLORIFY_DEMO_EMAIL && !process.env.GLORIFY_DEMO_PASSWORD) console.log("Demo sign-in: demo@glorify.local / glorify-demo");
  });
}

import os
import re
from collections import Counter
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, Image, PageBreak
)
from reportlab.lib.utils import ImageReader

SEVERITY_BUCKETS = ["Critical", "High", "Medium", "Low", "Informational"]
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
SEVERITY_COLOR = {
    "Critical": colors.HexColor("#7f1d1d"),
    "High": colors.HexColor("#b91c1c"),
    "Medium": colors.HexColor("#b45309"),
    "Low": colors.HexColor("#1d4ed8"),
    "Informational": colors.HexColor("#4b5563"),
}

OWASP_TOP_10 = [
    ("A01", "Broken Access Control"),
    ("A02", "Cryptographic Failures"),
    ("A03", "Injection"),
    ("A04", "Insecure Design"),
    ("A05", "Security Misconfiguration"),
    ("A06", "Vulnerable and Outdated Components"),
    ("A07", "Identification and Authentication Failures"),
    ("A08", "Software and Data Integrity Failures"),
    ("A09", "Security Logging and Monitoring Failures"),
    ("A10", "Server-Side Request Forgery (SSRF)"),
]

TOOL_COVERAGE = {
    "idor": {"A01"},
    "dual account": {"A01"},
    "sqli": {"A03"},
    "sqlmap": {"A03"},
    "auth": {"A07"},
    "clickjacking": {"A05"},
    "zap": {"A05"},
    "nuclei": {"A06"},
}

FALLBACK_REMEDIATION = {
    "A01": "Enforce a server-side authorization check that confirms the requesting user is allowed to access the object before returning it.",
    "A02": "Use strong, current TLS settings and encrypt sensitive data in transit and at rest.",
    "A03": "Use parameterized queries or prepared statements and validate input on the server side.",
    "A04": "Revisit the design of this flow and add the missing security control at the design level.",
    "A05": "Harden the configuration and set the missing security header to a safe, restrictive value.",
    "A06": "Update the affected component to a current, patched version and track it going forward.",
    "A07": "Strengthen authentication: enforce a strong password policy, rate-limit attempts, and secure the session.",
    "A08": "Verify the integrity and source of code and data before trusting or executing it.",
    "A09": "Add security logging and monitoring so this activity would be detected and alerted on.",
    "A10": "Validate and allow-list outbound request destinations to prevent server-side request forgery.",
    "Other": "Review the finding and apply the appropriate secure configuration or code fix for the affected component.",
}

def _esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

def _normalize_severity(value: str) -> str:
    s = str(value or "").strip().lower()
    if s.startswith("crit"):
        return "Critical"
    if s.startswith("high"):
        return "High"
    if s.startswith("med"):
        return "Medium"
    if s.startswith("low"):
        return "Low"
    return "Informational"

def _owasp_code(finding: dict) -> str:
    cat = str(finding.get("category", "") or "")
    m = re.match(r"\s*A(\d{2})\b", cat, re.IGNORECASE)
    if m:
        return "A" + m.group(1)
    text = (cat + " " + str(finding.get("description", "") or "")).lower()
    checks = [
        ("A03", ["sql injection", "sqli", "xss", "cross site scripting", "cross-site scripting", "injection", "command inject"]),
        ("A01", ["access control", "idor", "authorization", "directory browsing", "directory listing", ".git", ".env"]),
        ("A02", ["tls", "ssl", "certificate", "cipher", "cryptograph"]),
        ("A06", ["outdated", "vulnerable component", "cve", "known vuln", "jquery", "version disclos"]),
        ("A07", ["authentication", "login", "password", "session", "credential"]),
        ("A10", ["ssrf", "server-side request"]),
        ("A08", ["integrity", "deserial", "supply chain"]),
        ("A09", ["logging", "monitoring", "audit trail"]),
        ("A04", ["insecure design"]),
        ("A05", ["csp", "content security policy", "header", "clickjack", "x-frame", "misconfig",
                 "cookie", "cache", "cors", "cross-domain", "hsts", "strict-transport"]),
    ]
    for code, keywords in checks:
        if any(k in text for k in keywords):
            return code
    return "Other"

def _risk_summary_line(findings: list[dict]) -> str:
    if not findings:
        return "Overall risk: None. No issues were found in the categories tested."
    counts = Counter(_normalize_severity(f.get("severity")) for f in findings)
    headline = next(s for s in SEVERITY_BUCKETS if counts.get(s, 0) > 0)
    parts = [f"{counts[s]} {s.lower()}-severity" for s in SEVERITY_BUCKETS if counts.get(s, 0) > 0]
    total = sum(counts.values())
    verb = "issue was" if total == 1 else "issues were"
    return f"Overall risk: {headline}. {', '.join(parts)} {verb} found."

def _coverage_rows(findings: list[dict]) -> list[tuple]:
    found_counts: Counter = Counter()
    tested: set[str] = set()
    for f in findings:
        code = _owasp_code(f)
        found_counts[code] += 1
        tested.add(code)
        tool = str(f.get("tool", "") or "").lower()
        for key, cats in TOOL_COVERAGE.items():
            if key in tool:
                tested |= cats

    rows = []
    for code, name in OWASP_TOP_10:
        n = found_counts.get(code, 0)
        if n > 0:
            rows.append((f"{code}  {name}", "Tested", f"{n} finding(s)"))
        elif code in tested:
            rows.append((f"{code}  {name}", "Tested", "None found"))
        else:
            rows.append((f"{code}  {name}", "Not tested", "—"))
    if found_counts.get("Other", 0) > 0:
        rows.append(("Other (unmapped)", "Tested", f"{found_counts['Other']} finding(s)"))
    return rows

def generate_report(findings: list[dict], output_path: str = "pentest_report.pdf",
                    target: str = "Target Application",
                    narrative: dict | None = None,
                    pages: list[dict] | None = None) -> None:
    narrative = narrative or {}
    per_finding = narrative.get("per_finding", {}) if isinstance(narrative, dict) else {}

    indexed = list(enumerate(findings))
    indexed.sort(key=lambda pair: (
        SEVERITY_ORDER.get(_normalize_severity(pair[1].get("severity")), 4),
        _owasp_code(pair[1]),
        str(pair[1].get("tool", "")),
    ))

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], fontSize=20, spaceAfter=4)
    meta_style = ParagraphStyle("Meta", parent=styles["Normal"], fontSize=10, spaceAfter=2)
    note_style = ParagraphStyle("Note", parent=styles["Normal"], fontSize=9,
                                textColor=colors.HexColor("#555555"), spaceAfter=12)
    risk_style = ParagraphStyle("Risk", parent=styles["Normal"], fontSize=13,
                                textColor=colors.HexColor("#111827"), spaceBefore=6, spaceAfter=10,
                                borderPadding=8, backColor=colors.HexColor("#f3f4f6"), leading=17)
    h2_style = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13, spaceBefore=14, spaceAfter=4)
    body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, spaceAfter=6, leading=14)
    justify_style = ParagraphStyle("Justify", parent=styles["Normal"], fontSize=9.5,
                                   textColor=colors.HexColor("#374151"), spaceAfter=4, leading=13)
    mono_style = ParagraphStyle("Mono", parent=styles["Normal"], fontName="Courier",
                                fontSize=8.5, leading=11, backColor=colors.HexColor("#f3f4f6"),
                                borderPadding=6, spaceAfter=6)

    story = []
    story.append(Paragraph("Automated Pentest Report", title_style))
    story.append(Paragraph(f"<b>Target:</b> {_esc(target)}", meta_style))
    story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}", meta_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Generated by an autonomous agent running on Steel Computer. Findings should be "
        "independently verified before acting on them — see individual evidence per finding.",
        note_style))

    story.append(Paragraph(_esc(_risk_summary_line(findings)), risk_style))

    counts = Counter(_normalize_severity(f.get("severity")) for f in findings)
    table_data = [["Severity", "Count"]] + [
        [sev, str(counts[sev])] for sev in SEVERITY_BUCKETS if counts.get(sev, 0) > 0
    ] or [["Severity", "Count"]]
    if len(table_data) > 1:
        t = Table(table_data, colWidths=[1.7 * inch, 1 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
        story.append(Spacer(1, 8))

    if narrative.get("summary"):
        story.append(Paragraph("Executive Summary", h2_style))
        story.append(Paragraph(_esc(narrative["summary"]), body_style))
        story.append(Paragraph(
            "Detection by OWASP ZAP, Nuclei, sqlmap, and custom checks. Analysis and "
            "write-up authored by Claude (claude-sonnet-5) from those tool findings.",
            note_style))

    story.append(Paragraph("OWASP Top 10 Coverage", h2_style))
    story.append(Paragraph(
        "What each category's tooling actually exercised in this scan. “Not tested” means no "
        "tool meaningfully probed that category — it is not a clean bill of health.", note_style))
    cov_data = [["OWASP Category", "Status", "Result"]] + [list(r) for r in _coverage_rows(findings)]
    cov = Table(cov_data, colWidths=[3.5 * inch, 1.1 * inch, 1.6 * inch])
    cov_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    for r_i, row in enumerate(cov_data[1:], start=1):
        if row[1] == "Not tested":
            cov_style.append(("TEXTCOLOR", (0, r_i), (-1, r_i), colors.HexColor("#9ca3af")))
    cov.setStyle(TableStyle(cov_style))
    story.append(cov)
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#d1d5db")))

    story.append(Paragraph("Findings", h2_style))
    if not indexed:
        story.append(Paragraph("No findings were recorded for this scan.", body_style))
    for original_idx, f in indexed:
        sev = _normalize_severity(f.get("severity"))
        color = SEVERITY_COLOR.get(sev, colors.black)
        header = (f'<font color="{color.hexval()}">[{_esc(sev)}]</font> '
                  f'{_esc(f.get("category", "Uncategorized"))}')
        story.append(Paragraph(header, h2_style))

        prose = per_finding.get(str(original_idx), {}) if isinstance(per_finding, dict) else {}
        if prose.get("justification"):
            story.append(Paragraph(
                f'<i>Why {_esc(sev)}:</i> {_esc(prose["justification"])}', justify_style))

        story.append(Paragraph(f'<b>Tool:</b> {_esc(f.get("tool", "—"))}', body_style))
        story.append(Paragraph(
            f'<b>Endpoint:</b> <font face="Courier">{_esc(f.get("endpoint", "—"))}</font>', body_style))
        story.append(Paragraph(_esc(f.get("description", "")), body_style))
        if f.get("evidence"):
            story.append(Paragraph("<b>Evidence:</b>", body_style))
            evidence_text = _esc(str(f["evidence"])[:1000]).replace("\n", "<br/>")
            story.append(Paragraph(evidence_text, mono_style))

        remediation = prose.get("remediation") or FALLBACK_REMEDIATION.get(
            _owasp_code(f), FALLBACK_REMEDIATION["Other"])
        story.append(Paragraph(f'<b>Suggested remediation:</b> {_esc(remediation)}', body_style))

        shot = f.get("screenshot")
        if shot and os.path.exists(shot):
            try:
                iw, ih = ImageReader(shot).getSize()
                w = 5.5 * inch
                h = min(w * ih / iw, 3.6 * inch)
                w = h * iw / ih
                story.append(Spacer(1, 2))
                story.append(Image(shot, width=w, height=h))
            except Exception:
                pass

    story.append(PageBreak())
    story.append(Paragraph("Plain-Language Summary", h2_style))
    nontech = narrative.get("non_technical_summary")
    if not nontech:
        total = len(findings)
        if total == 0:
            nontech = ("We checked this application for the most common security weaknesses and "
                       "did not find any issues in the areas we were able to test. This is not a "
                       "guarantee the app is fully secure — only that these checks came back clean.")
        else:
            headline = _risk_summary_line(findings).split(".")[0].replace("Overall risk: ", "")
            nontech = (f"We checked this application for common security weaknesses and found {total} "
                       f"issue(s). The most serious is rated “{headline}”. We recommend fixing the "
                       "higher-severity items first. Each issue above explains what it is and how to "
                       "address it. These findings should be reviewed by someone technical before changes are made.")
    story.append(Paragraph(_esc(nontech), body_style))

    real_pages = [p for p in (pages or []) if p.get("screenshot") and os.path.exists(p["screenshot"])]
    if real_pages:
        story.append(PageBreak())
        story.append(Paragraph("Appendix: Crawled Pages", h2_style))
        story.append(Paragraph(
            "Screenshots captured by the Steel Browser crawl. Visual evidence and coverage "
            "reference — not a claim of exhaustive coverage.", note_style))
        for p in real_pages:
            story.append(Paragraph(
                f'<b>{_esc(p.get("title") or "(page)")}</b> — '
                f'<font face="Courier">{_esc(p.get("url", ""))}</font>', body_style))
            try:
                iw, ih = ImageReader(p["screenshot"]).getSize()
                w = 6.3 * inch
                h = w * ih / iw
                if h > 4.2 * inch:
                    h = 4.2 * inch
                    w = h * iw / ih
                story.append(Image(p["screenshot"], width=w, height=h))
            except Exception:
                story.append(Paragraph("(screenshot could not be embedded)", note_style))
            story.append(Spacer(1, 10))

    doc = SimpleDocTemplate(output_path, pagesize=letter,
                            topMargin=0.75 * inch, bottomMargin=0.75 * inch,
                            leftMargin=0.85 * inch, rightMargin=0.85 * inch)
    doc.build(story)

if __name__ == "__main__":
    sample_findings = [
        {"category": "A01: Broken Access Control (IDOR)", "tool": "HTTP (dual account)", "severity": "High",
         "description": "User B could read User A's basket by requesting its ID directly.",
         "endpoint": "http://localhost:3000/api/BasketItems/1",
         "evidence": '{"id": 1, "ProductId": 3, "quantity": 2, "UserId": 1}'},
        {"category": "A03: Injection (SQLi)", "tool": "sqlmap", "severity": "Critical",
         "description": "Login email parameter is injectable.", "endpoint": "/rest/user/login",
         "evidence": "Parameter: email (POST) ..."},
        {"category": "Content Security Policy (CSP) Header Not Set", "tool": "ZAP", "severity": "Medium",
         "description": "No CSP header present.", "endpoint": "http://localhost:3000/", "evidence": ""},
        {"category": "A06: Vulnerable Components", "tool": "Nuclei", "severity": "Low",
         "description": "Outdated jQuery.", "endpoint": "/vendor/jquery.min.js", "evidence": "jquery@2.1.4"},
    ]
    sample_narrative = {
        "summary": "The scan surfaced a critical SQL injection and a high-severity access-control flaw.",
        "non_technical_summary": "We found a serious flaw that could let someone log in as another user, "
                                 "plus a few configuration weaknesses. Fix the most serious ones first.",
        "per_finding": {
            "0": {"justification": "Direct object reference returned another user's data without an access check.",
                  "remediation": "Enforce a server-side check that the requester owns the object before returning it."},
            "1": {"justification": "sqlmap confirmed the parameter is injectable, allowing auth bypass.",
                  "remediation": "Use parameterized queries and validate input server-side."},
        },
    }
    generate_report(sample_findings, output_path="sample_report.pdf",
                    target="OWASP Juice Shop (demo)", narrative=sample_narrative)
    print("Sample report generated: sample_report.pdf")

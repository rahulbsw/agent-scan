from __future__ import annotations

import html
import json
from typing import TYPE_CHECKING

from agent_scan.skill_scanning.reporting import sanitized

if TYPE_CHECKING:
    from agent_scan.skill_scanning.models import Report


def text(value: object) -> str:
    """Escape markup and make control/bidi characters visible in report metadata."""
    return html.escape(json.dumps(str(value), ensure_ascii=True)[1:-1], quote=True)


def html_document(title: str, body: str) -> str:
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; '
        'base-uri &#39;none&#39;; form-action &#39;none&#39;">'
        f"<title>{text(title)}</title>"
        "<style>body{font:15px/1.5 system-ui,sans-serif;color:#202124;background:#fff;"
        "max-width:1200px;margin:24px auto;padding:0 16px}h1{font-size:24px}h2{font-size:18px}"
        "table{border-collapse:collapse;width:100%;margin:16px 0}th,td{text-align:left;"
        "vertical-align:top;border-bottom:1px solid #dadce0;padding:8px;overflow-wrap:anywhere}"
        ".table{overflow-x:auto}th{background:#f1f3f4}.note{color:#50565d}"
        "a{color:#006958}code{overflow-wrap:anywhere}details{margin:12px 0}"
        "@media(max-width:600px){table,tbody,tr,td{display:block}thead{display:none}"
        "tbody tr{border-bottom:1px solid #dadce0;padding:8px 0}td{border:0;padding:6px 0}"
        "td::before{content:attr(data-label);display:block;font-size:13px;font-weight:600;color:#50565d}"
        "td[colspan]::before{display:none}}"
        "</style></head><body>"
        f"<h1>{text(title)}</h1>{body}</body></html>"
    )


def render_html(report: Report) -> str:
    data = sanitized(report.model_dump())
    findings = data["findings"]
    active = sum(finding["suppression"] is None for finding in findings)
    body = (
        f"<p>Profile: {text(report.profile)} (experimental). Scanner: {text(report.scanner_version)}.</p>"
        f"<p>Execution: {'successful' if report.execution_successful else 'failed'}. "
        f"Coverage: <strong>{text(report.coverage.status)}</strong>. "
        f"Files read: {report.coverage.files_read}. Bytes read: {report.coverage.bytes_read}.</p>"
        f"<p>Active findings: {active}. Suppressed: {len(findings) - active}.</p>"
        '<div class="table"><table><thead><tr><th>Location</th><th>Rule</th>'
        "<th>Severity / confidence</th><th>Evidence and remediation</th></tr></thead><tbody>"
    )
    for finding in findings[:200]:
        suppression = finding["suppression"]
        state = f"Suppressed: {text(suppression['reason'])}" if suppression else "Active"
        body += (
            f'<tr><td data-label="Location">{text(finding["path"])}:{finding["line"]}:{finding["column"]}</td>'
            f'<td data-label="Rule">{text(finding["rule_id"])}<br>{text(finding["title"])}</td>'
            f'<td data-label="Severity / confidence">{text(finding["severity"])} / {text(finding["confidence"])}<br>{state}</td>'
            f'<td data-label="Evidence and remediation">{text(finding["message"])}<br>{text(finding["remediation"])}'
            f"<details><summary>Review context</summary><p>{text(finding['false_positive_rationale'])}</p>"
            f"<p>{text('; '.join(finding['references']))}</p></details></td></tr>"
        )
    if not findings:
        body += '<tr><td colspan="4">No findings from the selected rules. This is not a safety certification.</td></tr>'
    body += "</tbody></table></div>"
    if len(findings) > 200:
        body += "<p>Showing the first 200 findings. Use the JSON report for the full recorded finding list.</p>"
    body += "<h2>Coverage limitations</h2><ul>"
    for item in data["coverage"]["limitations"][:200]:
        body += f"<li>{text(item['path'])}: {text(item['reason'])}</li>"
    if not report.coverage.limitations:
        body += "<li>No profile coverage gaps recorded.</li>"
    body += "</ul>"
    if len(report.coverage.limitations) > 200:
        body += "<p>Showing the first 200 coverage limitations. See JSON for all recorded gaps.</p>"
    body += "<h2>Analysis scope</h2><ul>" + "".join(f"<li>{text(item)}</li>" for item in data["limitations"]) + "</ul>"
    return html_document("Open Agent Scan report", body)

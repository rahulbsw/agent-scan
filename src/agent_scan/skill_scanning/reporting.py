from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from agent_scan.redact import redact_text

if TYPE_CHECKING:
    from agent_scan.skill_scanning.models import Report

_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def sanitized(value):
    if isinstance(value, str):
        # Reports never include source text, but filenames can also contain credentials.
        return redact_text(value) or ""
    if isinstance(value, list):
        return [sanitized(item) for item in value]
    if isinstance(value, dict):
        # These schema fields contain scanner-generated evidence IDs, not source secrets.
        return {
            key: item
            if key in {"sha256", "fingerprint", "oasEvidence/v1"}
            and isinstance(item, str)
            and re.fullmatch(r"[a-f0-9]{64}", item)
            else sanitized(item)
            for key, item in value.items()
        }
    return value


def exit_code(report: Report, *, fail_on: str = "none", fail_on_incomplete: bool = False) -> int:
    if not report.execution_successful:
        return 2
    if fail_on_incomplete and report.coverage.status != "complete":
        return 1
    if fail_on != "none" and any(
        finding.suppression is None and _SEVERITY_ORDER[finding.severity] >= _SEVERITY_ORDER[fail_on]
        for finding in report.findings
    ):
        return 1
    return 0


def sarif(report: Report) -> dict:
    rules = {}
    results = []
    for finding in report.findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.false_positive_rationale},
            "properties": {
                "category": finding.category,
                "confidence": finding.confidence,
                "experimental": finding.experimental,
                "revision": finding.rule_revision,
                "references": finding.references,
            },
        }
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": "error" if finding.severity in ("high", "critical") else "warning",
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": quote(redact_text(finding.path) or "artifact", safe="/")},
                        "region": {"startLine": finding.line, "startColumn": finding.column},
                    }
                }
            ],
            "partialFingerprints": {"oasEvidence/v1": finding.fingerprint},
            "properties": {
                "severity": finding.severity,
                "confidence": finding.confidence,
                "remediation": finding.remediation,
                "experimental": finding.experimental,
            },
        }
        if finding.suppression:
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": finding.suppression["reason"],
                }
            ]
            result["properties"]["suppression"] = finding.suppression
        results.append(result)
    return sanitized(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Open Agent Scan",
                            "version": report.scanner_version,
                            "rules": [rules[key] for key in sorted(rules)],
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": report.execution_successful,
                            "toolExecutionNotifications": [
                                {"level": "warning", "message": {"text": f"{item.path}: {item.reason}"}}
                                for item in report.coverage.limitations
                            ],
                        }
                    ],
                    "results": results,
                    "properties": {
                        "schemaVersion": report.schema_version,
                        "profile": report.profile,
                        "coverage": report.coverage.model_dump(),
                        "limitations": report.limitations,
                    },
                }
            ],
        }
    )


def render(report: Report, output_format: str) -> str:
    if output_format == "html":
        from agent_scan.skill_scanning.html_report import render_html

        return render_html(report)
    if output_format == "sarif":
        return json.dumps(sarif(report), ensure_ascii=True, indent=2)
    data = sanitized(report.model_dump())
    if output_format == "json":
        return json.dumps(data, ensure_ascii=True, indent=2)

    # JSON string escaping neutralizes ANSI, line breaks and bidi controls in names.
    def display(value: str) -> str:
        return json.dumps(value, ensure_ascii=True)[1:-1]

    lines = [
        f"Open Agent Scan {report.scanner_version} | passive-text-v1 (experimental)",
        f"Coverage: {report.coverage.status}; {report.coverage.files_read} files, {report.coverage.bytes_read} bytes",
    ]
    for finding in data["findings"]:
        state = "suppressed" if finding["suppression"] else finding["severity"]
        lines.append(
            f"{display(finding['path'])}:{finding['line']}:{finding['column']} "
            f"[{state}/{finding['confidence']}] {finding['rule_id']}: {finding['message']}"
        )
    for item in data["coverage"]["limitations"]:
        lines.append(f"Not fully inspected: {display(item['path'])}: {item['reason']}")
    lines.extend(report.limitations)
    return "\n".join(lines)

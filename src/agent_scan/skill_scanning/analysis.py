from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING

from agent_scan import __version__
from agent_scan.rules import RULES
from agent_scan.skill_scanning.collector import BudgetExceeded, collect
from agent_scan.skill_scanning.models import Finding, Limits, Report

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_PATTERNS = (
    (
        "OAS-SKILL-001",
        re.compile(
            r"\b(?:ignore|disregard|override)[ \t]+(?:all[ \t]+)?"
            r"(?:previous|prior|system|developer)[ \t]+(?:instructions?|messages?|prompts?)\b",
            re.IGNORECASE,
        ),
        "Instruction text asks the agent to override an instruction boundary.",
        "Remove unauthorized overrides; inspect quoted examples in context.",
    ),
    (
        "OAS-SKILL-002",
        re.compile(
            r"\b(?:curl|wget)\b[^\r\n|;&]{0,2048}\|[ \t]*(?:sudo[ \t]+)?(?:bash|sh|zsh|python|node)\b",
            re.IGNORECASE,
        ),
        "Downloaded content is piped directly to an interpreter.",
        "Pin and verify downloaded content, inspect it, and require explicit execution approval.",
    ),
    (
        "OAS-SKILL-003",
        re.compile("[\u200b\u202a-\u202e\u2066-\u2069]"),
        "Text contains zero-width or bidirectional formatting worth reviewing.",
        "Review formatting in the original source; remove concealed instructions if present.",
    ),
)


def fingerprint(rule_id: str, revision: str, path: str, digest: str, line: int, column: int) -> str:
    payload = json.dumps([rule_id, revision, path, digest, line, column], ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def scan_skills(target: Path, limits: Limits | None = None, *, exclude: Path | None = None) -> Report:
    report = Report(scanner_version=__version__)
    limits = limits or Limits()

    def inspect_text(path: str, text: str, digest: str, check_time: Callable[[], None]) -> None:
        # Text stays local and ephemeral. Fixed messages avoid leaking source or secrets.
        for rule_id, pattern, message, remediation in _PATTERNS:
            rule = RULES[rule_id]
            for line_number, line in enumerate(text.splitlines(keepends=True), start=1):
                check_time()
                for match in pattern.finditer(line):
                    if len(report.findings) >= limits.max_findings:
                        raise BudgetExceeded("finding_limit")
                    column = match.start() + 1
                    report.findings.append(
                        Finding(
                            rule_id=rule_id,
                            rule_revision=rule.revision,
                            title=rule.title,
                            category=rule.category,
                            severity=rule.severity,
                            confidence=rule.confidence,
                            experimental=rule.experimental,
                            path=path,
                            line=line_number,
                            column=column,
                            message=message,
                            remediation=remediation,
                            references=list(rule.source_references),
                            false_positive_rationale=rule.false_positive_rationale,
                            fingerprint=fingerprint(rule_id, rule.revision, path, digest, line_number, column),
                        )
                    )

    collect(target, report, limits, inspect_text, exclude=exclude)
    report.findings.sort(key=lambda finding: (finding.path, finding.line, finding.column, finding.rule_id))
    report.artifacts.sort(key=lambda artifact: artifact.path)
    report.coverage.limitations.sort(key=lambda limitation: (limitation.path, limitation.reason))
    return report
